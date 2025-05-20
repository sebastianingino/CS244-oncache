package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/florianl/go-tc"
	"github.com/florianl/go-tc/core"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

const DEFAULT_NETDEV = "ens4"
const DEFAULT_OBJ_PATH = "../kernel/ebpf_plugin.o"

func setup(netdev *net.Interface) error {
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
			fmt.Fprintf(os.Stderr, "could not close rtnetlink socket: %v\n", err)
		}
	}()

	// For enhanced error messages from the kernel, it is recommended to set
	// option `NETLINK_EXT_ACK`, which is supported since 4.12 kernel.
	if err := tcnl.SetOption(netlink.ExtendedAcknowledge, true); err != nil {
		return fmt.Errorf("could not set option ExtendedAcknowledge: %v", err)
	}

	// Create qdisc on host
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

func get_containers(clientset *kubernetes.Clientset, hostname *string) ([]string, error) {
	// Get all running pods on current node
	pods, err := clientset.CoreV1().Pods("").List(context.Background(), metav1.ListOptions{
		FieldSelector: fmt.Sprintf("spec.nodeName=%s,status.phase=Running", *hostname),
	})
	if err != nil {
		return nil, fmt.Errorf("could not list pods: %v", err)
	}

	// Get all running containers in the pods
	containers := make([]string, 0)
	for _, pod := range pods.Items {
		for _, container := range pod.Status.ContainerStatuses {
			if container.State.Running != nil {
				containers = append(containers, container.ContainerID)
			}
		}
	}

	return containers, nil
}

func teardown(netdev *net.Interface) {
	// open a rtnetlink socket
	tcnl, err := tc.Open(&tc.Config{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not open rtnetlink socket: %v\n", err)
		return
	}
	defer func() {
		if err := tcnl.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "could not close rtnetlink socket: %v\n", err)
		}
	}()

	// Delete qdisc on host
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
		fmt.Fprintf(os.Stderr, "could not delete qdisc: %v\n", err)
	}
}

func load_program(prog *ebpf.Program, direction uint32, netdev *net.Interface) error {
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

	// open a rtnetlink socket
	tcnl, err := tc.Open(&tc.Config{})
	if err != nil {
		return fmt.Errorf("could not open rtnetlink socket: %v", err)
	}
	defer func() {
		if err := tcnl.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "could not close rtnetlink socket: %v\n", err)
		}
	}()

	// Attach the eBPF program to the network device
	fd := uint32(prog.FD())
	flags := uint32(0)

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

func run(hostname, kubeconfig, netdev, objPath *string) error {
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

	// Get the network device ID
	host, err := net.InterfaceByName(*netdev)
	if err != nil {
		return fmt.Errorf("could not get network device ID: %v", err)
	}

	// Run setup
	if err := setup(host); err != nil {
		return fmt.Errorf("could not set up: %v", err)
	}
	defer teardown(host)

	// Load the eBPF collection spec
	spec, err := ebpf.LoadCollectionSpec(*objPath)
	if err != nil {
		return fmt.Errorf("could not load eBPF collection spec: %v", err)
	}

	// Make directory for pinned maps
	os.MkdirAll("/sys/fs/bpf/tc/globals", 0755)
	defer os.RemoveAll("/sys/fs/bpf/tc/globals")

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

	// Print the loaded maps
	fmt.Printf("Found %d maps:\n", len(coll.Maps))
	for name := range coll.Maps {
		fmt.Printf("%s\n", name)
	}

	// Print the loaded programs
	fmt.Printf("Found %d programs:\n", len(coll.Programs))
	for name := range coll.Programs {
		fmt.Printf("%s\n", name)
	}

	// Load the egress init program on the hsot
	if err := load_program(coll.Programs["egress_init"], tc.HandleMinEgress, host); err != nil {
		return fmt.Errorf("could not load egress init program: %v", err)
	}

	// Load the ingress program on the host
	if err := load_program(coll.Programs["ingress"], tc.HandleMinIngress, host); err != nil {
		return fmt.Errorf("could not load ingress program: %v", err)
	}

	// Get the list of containers
	containers, err := get_containers(clientset, hostname)
	if err != nil {
		return fmt.Errorf("could not get containers: %v", err)
	}
	// Print the list of containers
	for _, container := range containers {
		fmt.Println(container)
	}

	// Wait for 5 seconds
	time.Sleep(5 * time.Second)

	return nil
}

func main() {
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

	// Set up the network device flag
	var netdev = flag.String("netdev", DEFAULT_NETDEV, "(optional) network device to use")

	// Set up the object path flag
	var objPath = flag.String("objpath", DEFAULT_OBJ_PATH, "(optional) path to the eBPF object file")

	// Parse the flags
	flag.Parse()

	if err := run(hostname, kubeconfig, netdev, objPath); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
