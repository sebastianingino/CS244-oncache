package main

import (
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/buger/jsonparser"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/florianl/go-tc"
	"github.com/florianl/go-tc/core"
	"github.com/lmittmann/tint"
	"github.com/mdlayher/netlink"
	vnl "github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/remotecommand"
	"k8s.io/client-go/util/homedir"
	criV1 "k8s.io/cri-api/pkg/apis/runtime/v1"
)

const DEFAULT_HOST_NETDEV = "ens4"
const DEFAULT_POD_NETDEV = "eth0"
const DEFAULT_OBJ_PATH = "../kernel/ebpf_plugin.o"

func createQdisc(netdev *net.Interface, tcnl *tc.Tc) error {
	// Create clsact qdisc on interface
	qdisc := tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(netdev.Index),
			Handle:  core.BuildHandle(tc.HandleRoot, 0x0000),
			Parent:  tc.HandleIngress,
			Info:    0,
		},
		Attribute: tc.Attribute{
			Kind: "clsact",
		},
	}
	if err := tcnl.Qdisc().Add(&qdisc); err != nil {
		return fmt.Errorf("could not add qdisc: %v", err)
	}

	return nil
}

func deleteQdisc(netdev *net.Interface, tcnl *tc.Tc) error {
	// Delete clsact qdisc on interface
	qdisc := tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(netdev.Index),
			Handle:  core.BuildHandle(tc.HandleRoot, 0x0000),
			Parent:  tc.HandleIngress,
			Info:    0,
		},
		Attribute: tc.Attribute{
			Kind: "clsact",
		},
	}
	if err := tcnl.Qdisc().Delete(&qdisc); err != nil {
		return fmt.Errorf("could not delete qdisc: %v", err)
	}

	return nil
}

func getContainers(clientset *kubernetes.Clientset, hostname *string) (mapset.Set[string], error) {
	// Get all running pods on current node
	pods, err := clientset.CoreV1().Pods("").List(context.Background(), metav1.ListOptions{
		FieldSelector: fmt.Sprintf("spec.nodeName=%s,status.phase=Running", *hostname),
	})
	if err != nil {
		return nil, fmt.Errorf("could not list pods: %v", err)
	}

	// Get all running containers in the pods
	containers := mapset.NewSet[string]()
	for _, pod := range pods.Items {
		for _, container := range pod.Status.ContainerStatuses {
			if container.State.Running != nil {
				containers.Add(container.ContainerID)
			}
		}
	}

	return containers, nil
}

func loadProgram(prog *ebpf.Program, direction uint32, netdev *net.Interface, tcnl *tc.Tc) error {
	// Check if the program is a TC program
	if prog == nil {
		return fmt.Errorf("program is nil")
	}
	if prog.Type() != ebpf.SchedCLS {
		return fmt.Errorf("program is not a TC program: %v", prog.Type())
	}

	// Check the direction
	if direction != tc.HandleMinIngress && direction != tc.HandleMinEgress {
		return fmt.Errorf("invalid direction: %v", direction)
	}

	// Attach the eBPF program to the network device
	fd := uint32(prog.FD())
	flags := uint32(nl.TCA_BPF_FLAG_ACT_DIRECT)

	filter := tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(netdev.Index),
			Handle:  0,
			Parent:  core.BuildHandle(tc.HandleRoot, direction),
			Info:    0x300,
		},
		Attribute: tc.Attribute{
			Kind: "bpf",
			BPF: &tc.Bpf{
				FD:    &fd,
				Flags: &flags,
			},
		},
	}

	if err := tcnl.Filter().Add(&filter); err != nil {
		return fmt.Errorf("could not add filter: %v", err)
	}

	return nil
}

func setInterface(hostInterface *ebpf.Variable, netdev *net.Interface) error {
	// Check if variable exists
	if hostInterface == nil {
		return fmt.Errorf("hostInterface variable is nil")
	}

	// Value struct
	type InterfaceData struct {
		Mac [6]byte
		Ip  uint32
	}

	// Get values for struct
	if len(netdev.HardwareAddr) != 6 {
		return fmt.Errorf("failed getting hardware addr, got %v", netdev.HardwareAddr)
	}

	ips, err := netdev.Addrs()
	if err != nil {
		return fmt.Errorf("failed to get network interface address: %v", err)
	}
	if len(ips) == 0 {
		return fmt.Errorf("found no network interface addresses")
	}
	ip, _, err := net.ParseCIDR(ips[0].String())
	if err != nil {
		return fmt.Errorf("failed to convert IP: %v", err)
	}
	ipv4 := ip.To4()
	if ipv4 == nil {
		return fmt.Errorf("failed to convert IP %v to v4", ip)
	}

	// Populate struct
	value := InterfaceData{
		Mac: [6]byte(netdev.HardwareAddr),
		Ip:  binary.NativeEndian.Uint32(ipv4),
	}

	// Set variable
	if err := hostInterface.Set(value); err != nil {
		return fmt.Errorf("failed adding value to map: %v", err)
	}

	slog.Debug("added network interface", slog.Any("interface", value))

	return nil
}

func setEgressRules(clientset *kubernetes.Clientset, config *rest.Config, rules []string) error {
	// Get the antrea-agent pods
	pods, err := clientset.CoreV1().Pods("kube-system").List(context.Background(), metav1.ListOptions{
		FieldSelector: "status.phase=Running",
		LabelSelector: "app=antrea,component=antrea-agent",
	})
	if err != nil {
		return fmt.Errorf("could not list pods: %v", err)
	}
	if len(pods.Items) == 0 {
		return fmt.Errorf("no antrea-agent pods found")
	}

	// Command
	// See: https://www.openvswitch.org/support/dist-docs/ovs-ofctl.8.html
	// And: https://antrea.io/docs/main/docs/design/ovs-pipeline/
	// Note: I try SO hard to keep everything in Goland but we have to use the shell :(
	cmd := []string{"ovs-ofctl", "mod-flows", "br-int"}

	for _, pod := range pods.Items {
		for _, rule := range rules {
			req := clientset.CoreV1().RESTClient().Post().Resource("pods").
				Name(pod.Name).
				Namespace("kube-system").
				SubResource("exec")
			req.VersionedParams(
				&v1.PodExecOptions{
					Command:   append(cmd, rule),
					Container: "antrea-agent",
					Stderr:    true,
					Stdout:    true,
					Stdin:     false,
					TTY:       false,
				},
				scheme.ParameterCodec,
			)
			exec, err := remotecommand.NewSPDYExecutor(config, "POST", req.URL())
			if err != nil {
				return fmt.Errorf("could not create executor: %v", err)
			}
			if err := exec.StreamWithContext(context.Background(), remotecommand.StreamOptions{
				Stdin:  nil,
				Stdout: os.Stdout,
				Stderr: os.Stderr,
				Tty:    false,
			}); err != nil {
				return fmt.Errorf("could not execute command: %v", err)
			}
		}
	}

	return nil
}

func loadContainerPlugin(containerPid int, containerNetdev *string, coll *ebpf.Collection) (int, error) {
	// Lock the OS thread so we don't accidentally switch namespaces
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Save current network namespace
	hostNetNS, err := netns.Get()
	if err != nil {
		return 0, fmt.Errorf("failed to get host network namespace: %v", err)
	}
	defer hostNetNS.Close()

	// Get container network namespace
	containerNetNS, err := netns.GetFromPid(containerPid)
	if err != nil {
		return 0, fmt.Errorf("failed to get container network namespace: %v", err)
	}
	defer containerNetNS.Close()

	// Step into container net namespace
	netns.Set(containerNetNS)
	defer func() {
		if err := netns.Set(hostNetNS); err != nil {
			// We should never fail to set the host namespace but if we do, we should freak out
			panic(fmt.Errorf("failed to set host network namespace: %v", err))
		}
	}()

	// Get the container network interface
	netInterface, err := net.InterfaceByName(*containerNetdev)
	if err != nil {
		return 0, fmt.Errorf("failed to get container network interface: %v", err)
	}

	// open a rtnetlink socket
	tcnl, err := tc.Open(&tc.Config{})
	if err != nil {
		return 0, fmt.Errorf("could not open rtnetlink socket: %v", err)
	}
	defer func() {
		if err := tcnl.Close(); err != nil {
			slog.Error("could not close rtnetlink socket", slog.Any("error", err))
		}
	}()

	// For enhanced error messages from the kernel, it is recommended to set
	// option `NETLINK_EXT_ACK`, which is supported since 4.12 kernel.
	if err := tcnl.SetOption(netlink.ExtendedAcknowledge, true); err != nil {
		return 0, fmt.Errorf("could not set option ExtendedAcknowledge: %v", err)
	}

	// Add a qdisc to the container interface
	if err := createQdisc(netInterface, tcnl); err != nil {
		return 0, fmt.Errorf("could not create container qdisc: %v", err)
	}

	// Load the ingress init program on the container
	if err := loadProgram(coll.Programs["ingress_init"], tc.HandleMinIngress, netInterface, tcnl); err != nil {
		return 0, fmt.Errorf("could not load container program: %v", err)
	}

	// Get the parent link index
	nlInterface, _ := vnl.LinkByIndex(netInterface.Index)

	return nlInterface.Attrs().ParentIndex, nil
}

func addIngressData(pod *v1.Pod, vethIdx int, coll *ebpf.Collection) error {
	// Get the pod IP as key
	ip := net.ParseIP(pod.Status.PodIP)
	if ip == nil {
		return fmt.Errorf("failed to parse pod IP: %v", pod.Status.PodIP)
	}
	ipv4 := ip.To4()
	if ipv4 == nil {
		return fmt.Errorf("failed to convert pod IP to v4: %v", pod.Status.PodIP)
	}

	// Add the pod veth index to the ingress map
	type IngressData struct {
		VethIdx uint32
		Ethhdr  [14]byte
	}

	data := IngressData{
		VethIdx: uint32(vethIdx),
	}

	// Get the ingress map
	ingressMap, ok := coll.Maps["ingress_cache"]
	if !ok {
		return fmt.Errorf("ingress_cache map not found")
	}

	var (
		key [4]byte
		value IngressData
		entries = ingressMap.Iterate()
		size = 0
	)

	// Iterate over the ingress map to get the size
	for entries.Next(&key, &value) {
		size++
	}
	slog.Info("ingress_cache map size", slog.Int("size", size))

	// Convert the IP to a uint32 for the map key
	if err := ingressMap.Put(binary.NativeEndian.Uint32(ipv4), data); err != nil {
		return fmt.Errorf("failed to add pod data to ingress_cache map: %v", err)
	}

	// Get the ingress map
	ingressMap, ok := coll.Maps["ingress_cache"]
	if !ok {
		return fmt.Errorf("ingress_cache map not found")
	}

	var (
		key [4]byte
		value IngressData
		entries = ingressMap.Iterate()
		size = 0
	)

	// Iterate over the ingress map to get the size
	for entries.Next(&key, &value) {
		size++
	}
	slog.Info("ingress_cache map size", slog.Int("size", size))

	slog.Debug("added pod data to ingress_cache", slog.Any("key", binary.NativeEndian.Uint32(ipv4)), slog.Any("value", data))

	return nil
}

func initContainer(pod *v1.Pod, container v1.ContainerStatus, criClient criV1.RuntimeServiceClient, containerNetdev *string, coll *ebpf.Collection) error {
	slog.Info("Initializing container on pod", slog.Any("pod", pod.Name), slog.Any("container", container.ContainerID))

	// Get the container ID
	idx := strings.Index(container.ContainerID, "://")
	if idx < 0 {
		return fmt.Errorf("invalid container ID: %s", container.ContainerID)
	}

	// Get container status
	status, err := criClient.ContainerStatus(context.Background(), &criV1.ContainerStatusRequest{
		ContainerId: container.ContainerID[idx+3:],
		Verbose:     true, // Get extra info: needed for pid
	})
	if err != nil {
		return fmt.Errorf("failed to get container info: %v", err)
	}
	info, ok := status.Info["info"]
	if !ok {
		return fmt.Errorf("failed to get container info")
	}

	// Get container pid
	// Note: this makes me sad (you should see the raw json)
	pid, err := jsonparser.GetInt([]byte(info), "pid")
	if err != nil {
		return fmt.Errorf("failed to get pid from container info: %v", err)
	}

	// Load the container plugin
	vethIdx, err := loadContainerPlugin(int(pid), containerNetdev, coll)
	if err != nil {
		return fmt.Errorf("failed to load container plugin: %v", err)
	}
	slog.Debug("Loaded container plugin", slog.Any("vethIdx", vethIdx))

	// Get the veth interface
	veth, err := net.InterfaceByIndex(vethIdx)
	if err != nil {
		return fmt.Errorf("failed to get veth interface: %v", err)
	}

	// open a rtnetlink socket
	tcnl, err := tc.Open(&tc.Config{})
	if err != nil {
		return fmt.Errorf("could not open rtnetlink socket: %v", err)
	}
	defer func() {
		if err := tcnl.Close(); err != nil {
			slog.Error("could not close rtnetlink socket", slog.Any("error", err))
		}
	}()

	// For enhanced error messages from the kernel, it is recommended to set
	// option `NETLINK_EXT_ACK`, which is supported since 4.12 kernel.
	if err := tcnl.SetOption(netlink.ExtendedAcknowledge, true); err != nil {
		return fmt.Errorf("could not set option ExtendedAcknowledge: %v", err)
	}

	// Add a qdisc to the veth interface
	if err := createQdisc(veth, tcnl); err != nil {
		return fmt.Errorf("could not create veth qdisc: %v", err)
	}

	// Load the egress program on the veth interface
	// Note: this is an ingress program as the packets enter from the container to the veth interface
	if err := loadProgram(coll.Programs["egress"], tc.HandleMinIngress, veth, tcnl); err != nil {
		return fmt.Errorf("could not load veth program: %v", err)
	}

	// Add the pod data to the ingress map
	if err := addIngressData(pod, vethIdx, coll); err != nil {
		return fmt.Errorf("failed to add pod data to ingress_cache map: %v", err)
	}

	slog.Debug("Initialized container", slog.Any("pod", pod.Name), slog.Any("container", container.ContainerID))

	return nil
}

func retireContainer(pod *v1.Pod, container v1.ContainerStatus, criClient criV1.RuntimeServiceClient) error {
	slog.Info("Retiring container on pod", slog.Any("pod", pod.Name), slog.Any("container", container.ContainerID))
	return nil
}

func watchContainers(clientset *kubernetes.Clientset, hostname *string, containerNetdev *string, coll *ebpf.Collection) error {
	// Get the initial list of containers
	containers, err := getContainers(clientset, hostname)
	if err != nil {
		return fmt.Errorf("could not get containers: %v", err)
	}
	slog.Debug("Found containers", slog.Any("containers", containers))

	slog.Info("Watching for new containers...")

	// Connect to the CRI runtime
	conn, err := grpc.NewClient("unix:///run/containerd/containerd.sock", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		panic(err)
	}
	defer func() {
		if conn.Close() != nil {
			slog.Error("could not close connection to CRI runtime", slog.Any("error", err))
		}
	}()

	// Create a new CRI runtime client
	criClient := criV1.NewRuntimeServiceClient(conn)

	// Watch for new containers
	watcher, err := clientset.CoreV1().Pods("default").Watch(context.Background(), metav1.ListOptions{
		FieldSelector: fmt.Sprintf("spec.nodeName=%s", *hostname),
	})
	if err != nil {
		return fmt.Errorf("could not watch pods: %v", err)
	}

	// Catch SIGINT signal to stop the watcher
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stop
		watcher.Stop()
		slog.Info("Stopping watcher...")
	}()
	defer watcher.Stop()

	slog.Info("Press Ctrl+C to quit.")

	for event := range watcher.ResultChan() {
		switch event.Type {
		case watch.Added, watch.Modified:
			pod, ok := event.Object.(*v1.Pod)
			if !ok {
				slog.Error("could not cast event object to pod", slog.Any("event", event))
				continue
			}
			if pod.Status.Phase == v1.PodRunning {
				for _, container := range pod.Status.ContainerStatuses {
					if container.State.Running != nil && !containers.Contains(container.ContainerID) {
						// Initialize container
						if err := initContainer(pod, container, criClient, containerNetdev, coll); err != nil {
							slog.Error("could not initialize container", slog.Any("error", err))
							continue
						}
						// Add container to set
						containers.Add(container.ContainerID)
					}
				}
			}
		case watch.Deleted:
			pod, ok := event.Object.(*v1.Pod)
			if !ok {
				slog.Error("could not cast event object to pod", slog.Any("event", event))
				continue
			}
			if pod.Status.Phase == v1.PodSucceeded || pod.Status.Phase == v1.PodFailed {
				for _, container := range pod.Status.ContainerStatuses {
					if container.State.Terminated != nil && containers.Contains(container.ContainerID) {
						// Retire container
						if err := retireContainer(pod, container, criClient); err != nil {
							slog.Error("could not retire container", slog.Any("error", err))
							continue
						}
						// Remove container from set
						containers.Remove(container.ContainerID)
					}
				}
			}
		}
	}

	return nil
}

func run(hostname, kubeconfig, hostNetdev, containerNetdev, objPath *string) error {
	// Build the Kubernetes client configuration
	config, err := clientcmd.BuildConfigFromFlags("", *kubeconfig)
	if err != nil {
		return fmt.Errorf("could not build kubeconfig: %v", err)
	}

	// Create the Kubernetes clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("could not create Kubernetes clientset: %v", err)
	}

	// Get the host network interface
	host, err := net.InterfaceByName(*hostNetdev)
	if err != nil {
		return fmt.Errorf("could not get host network interface: %v", err)
	}

	// Remove rlimit
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("could not remove rlimit: %v", err)
	}

	// open a rtnetlink socket
	tcnl, err := tc.Open(&tc.Config{})
	if err != nil {
		return fmt.Errorf("could not open rtnetlink socket: %v", err)
	}
	defer func() {
		if err := tcnl.Close(); err != nil {
			slog.Error("could not close rtnetlink socket", slog.Any("error", err))
		}
	}()

	// For enhanced error messages from the kernel, it is recommended to set
	// option `NETLINK_EXT_ACK`, which is supported since 4.12 kernel.
	if err := tcnl.SetOption(netlink.ExtendedAcknowledge, true); err != nil {
		return fmt.Errorf("could not set option ExtendedAcknowledge: %v", err)
	}

	// Create qdisc on host
	if err := createQdisc(host, tcnl); err != nil {
		return fmt.Errorf("could not create host qdisc: %v", err)
	}
	defer func() {
		if err := deleteQdisc(host, tcnl); err != nil {
			slog.Error("could not delete host qdisc", slog.Any("error", err))
		}
	}()

	// Load the eBPF collection spec
	spec, err := ebpf.LoadCollectionSpec(*objPath)
	if err != nil {
		return fmt.Errorf("could not load eBPF collection spec: %v", err)
	}

	// Make directory for pinned maps
	if err := os.MkdirAll("/sys/fs/bpf/tc/globals", 0755); err != nil {
		return fmt.Errorf("could not create directory for pinned maps: %v", err)
	}
	defer func() {
		if err := os.RemoveAll("/sys/fs/bpf/tc/globals"); err != nil {
			slog.Error("could not remove directory for pinned maps", slog.Any("error", err))
		}
	}()

	// Load the eBPF collection
	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			// Pin the maps to the filesystem
			PinPath: "/sys/fs/bpf/tc/globals",
		},
	})
	if err != nil {
		return fmt.Errorf("could not create eBPF collection: %v", err)
	}
	defer coll.Close()

	slog.Debug("Found maps", slog.Any("maps", coll.Maps))
	slog.Debug("Found programs", slog.Any("programs", coll.Programs))

	// Load the egress init program on the host
	if err := loadProgram(coll.Programs["egress_init"], tc.HandleMinEgress, host, tcnl); err != nil {
		return fmt.Errorf("could not load egress init program: %v", err)
	}

	// Load the ingress program on the host
	if err := loadProgram(coll.Programs["ingress"], tc.HandleMinIngress, host, tcnl); err != nil {
		return fmt.Errorf("could not load ingress program: %v", err)
	}

	// Populate host_interface with host information
	if err := setInterface(coll.Variables["host_interface"], host); err != nil {
		return fmt.Errorf("failed to add host interface to host_interface: %v", err)
	}

	// Set up the egress rules
	rules := []string{
		"table=ConntrackState, priority=200,ct_state=-new+trk,ct_mark=0x10/0x10,ip actions=load:0x1->NXM_OF_IP_TOS[3],load:0x1->NXM_NX_REG0[9],resubmit(,AntreaPolicyEgressRule)",
		"table=ConntrackState, priority=190,ct_state=-new+trk,ip actions=load:0x1->NXM_OF_IP_TOS[3],resubmit(,AntreaPolicyEgressRule)",
	}
	if err := setEgressRules(clientset, config, rules); err != nil {
		return fmt.Errorf("could not set up egress rules: %v", err)
	}
	defer func() {
		// Remove the egress rules
		rules := []string{
			"table=ConntrackState, priority=200,ct_state=-new+trk,ct_mark=0x10/0x10,ip actions=load:0x1->NXM_NX_REG0[9],resubmit(,AntreaPolicyEgressRule)",
			"table=ConntrackState, priority=190,ct_state=-new+trk,ip actions=resubmit(,AntreaPolicyEgressRule)",
		}
		if err := setEgressRules(clientset, config, rules); err != nil {
			slog.Error("could not remove egress rules", slog.Any("error", err))
		}
	}()

	// Watch for new containers
	if err := watchContainers(clientset, hostname, containerNetdev, coll); err != nil {
		return fmt.Errorf("could not watch containers: %v", err)
	}

	return nil
}

func main() {
	// Set up logging
	slog.SetDefault(slog.New(
		tint.NewHandler(os.Stderr, &tint.Options{
			Level:      slog.LevelInfo,
			TimeFormat: time.Kitchen,
		}),
	))

	// Set up kubeconfig flag
	var kubeconfig *string
	if home := homedir.HomeDir(); home != "" {
		kubeconfig = flag.String("kubeconfig", filepath.Join(home, ".kube", "config"), "(optional) absolute path to the kubeconfig file")
	} else {
		kubeconfig = flag.String("kubeconfig", "", "absolute path to the kubeconfig file")
	}

	// Set up hostname flag
	var hostname *string
	if host, err := os.Hostname(); host != "" && err == nil {
		hostname = flag.String("hostname", host, "(optional) hostname of the node")
	} else {
		hostname = flag.String("hostname", "", "hostname of the node")
	}

	// Set up the host network device flag
	var hostNetdev = flag.String("hostNetdev", DEFAULT_HOST_NETDEV, "(optional) host network device to use")

	// Set up the container network device flag
	var containerNetdev = flag.String("containerNetdev", DEFAULT_POD_NETDEV, "(optional) container network device to use")

	// Set up the object path flag
	var objPath = flag.String("objpath", DEFAULT_OBJ_PATH, "(optional) path to the eBPF object file")

	// Parse the flags
	flag.Parse()

	if err := run(hostname, kubeconfig, hostNetdev, containerNetdev, objPath); err != nil {
		slog.Error("Error running oncache", slog.Any("error", err))
		os.Exit(1)
	}
}
