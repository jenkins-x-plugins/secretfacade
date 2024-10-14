package kubernetesiam

import (
	"fmt"
	"path/filepath"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

func InClusterClient() (kubernetes.Interface, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("error getting in cluster config for k8s: %w", err)
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("error creating clientset from in cluster config for k8s: %w", err)
	}
	return clientset, nil
}

func OutOfClusterClient() (kubernetes.Interface, error) {
	kubeconfig := filepath.Join(homedir.HomeDir(), ".kube", "config")

	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("error getting config for out of cluster k8s: %w", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("error creating clientset for out of cluster k8s: %w", err)
	}
	return clientset, nil
}

func GetClient() (kubernetes.Interface, error) {
	inCluster, err := InClusterClient()
	if err == nil {
		return inCluster, nil
	}

	outOfCluster, err := OutOfClusterClient()
	if err == nil {
		return outOfCluster, nil
	}

	return nil, fmt.Errorf("unable to configure kubernetes client")
}
