package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"

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

func setup(clientset *kubernetes.Clientset, hostname *string, netdev *string) ([]string, error) {
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

	// Get the network device ID
	devID, err := net.InterfaceByName(*netdev)
	if err != nil {
		return nil, fmt.Errorf("could not get network device ID: %v", err)
	}

	// open a rtnetlink socket
	tcnl, err := tc.Open(&tc.Config{})
	if err != nil {
		return nil, fmt.Errorf("could not open rtnetlink socket: %v", err)
	}
	defer func() {
		if err := tcnl.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "could not close rtnetlink socket: %v\n", err)
		}
	}()

	// For enhanced error messages from the kernel, it is recommended to set
	// option `NETLINK_EXT_ACK`, which is supported since 4.12 kernel.
	if err := tcnl.SetOption(netlink.ExtendedAcknowledge, true); err != nil {
		return nil, fmt.Errorf("could not set option ExtendedAcknowledge: %v", err)
	}

	// Create qdisc on host
	qdisc := tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(devID.Index),
			Handle:  core.BuildHandle(tc.HandleRoot, 0x0000),
			Parent:  tc.HandleIngress,
			Info:    0,
		},
		Attribute: tc.Attribute{
			Kind: "clsact",
		},
	}
	if err := tcnl.Qdisc().Add(&qdisc); err != nil {
		return nil, fmt.Errorf("could not add qdisc: %v", err)
	}

	return containers, nil
}

func teardown(netdev *string) {
	// Get the network device ID
	devID, err := net.InterfaceByName(*netdev)
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not get network device ID: %v\n", err)
		return
	}

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
			Ifindex: uint32(devID.Index),
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

func load_program() {

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

	// Parse the flags
	flag.Parse()

	// Build the Kubernetes client configuration
	config, err := clientcmd.BuildConfigFromFlags("", *kubeconfig)
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not build kubeconfig: %v\n", err)
		os.Exit(1)
	}

	// Create the Kubernetes clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not create Kubernetes clientset: %v\n", err)
		os.Exit(1)
	}

	// Run setup and get the list of containers
	containers, err := setup(clientset, hostname, netdev)
	defer teardown(netdev)
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not set up: %v\n", err)
		os.Exit(1)
	}

	for _, container := range containers {
		fmt.Println(container)
	}
}
