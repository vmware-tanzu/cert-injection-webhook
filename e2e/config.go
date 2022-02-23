package e2e

import (
	"flag"
	"os"
	"os/user"
	"path"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

var (
	clientSetup   sync.Once
	k8sClient     *kubernetes.Clientset
	clusterConfig *rest.Config
	err           error
)

func getClient(t *testing.T) (kubernetes.Interface, error) {
	clientSetup.Do(func() {
		kubeconfig := flag.String("kubeconfig", getKubeConfig(), "Path to a kubeconfig. Only required if out-of-cluster.")
		masterURL := flag.String("master", "", "The address of the Kubernetes API server. Overrides any value in kubeconfig. Only required if out-of-cluster.")

		flag.Parse()

		clusterConfig, err = clientcmd.BuildConfigFromFlags(*masterURL, *kubeconfig)
		require.NoError(t, err)

		k8sClient, err = kubernetes.NewForConfig(clusterConfig)
		require.NoError(t, err)
	})

	return k8sClient, nil
}

func getKubeConfig() string {
	if config, found := os.LookupEnv("KUBECONFIG"); found {
		return config
	}
	if usr, err := user.Current(); err == nil {
		return path.Join(usr.HomeDir, ".kube/config")
	}
	return ""
}
