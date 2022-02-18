package e2e

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/user"
	"path"
	"sync"
	"testing"

	jsonpatch "github.com/evanphx/json-patch"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const namespace = "cert-injection-webhook"

var (
	clientSetup   sync.Once
	configSetup   sync.Once
	k8sClient     *kubernetes.Clientset
	clusterConfig *rest.Config
	config        *testConfig
	err           error
)

type testConfig struct {
	annotations []string
	labels      []string
	cert        string
	httpsProxy  string
	httpProxy   string
	noProxy     string
}

func getTestConfig(t *testing.T, ctx context.Context, client kubernetes.Interface) *testConfig {
	configSetup.Do(func() {
		httpProxy := "some-http-proxy"
		noProxy := "some-no-proxy"
		httpsProxy := "some-https-proxy"
		cert := "some-cert"

		annotations, labels := setArgs(t, ctx, client)
		updateConfigMap(t, ctx, client, "http-proxy", map[string]string{"value": httpProxy})
		updateConfigMap(t, ctx, client, "https-proxy", map[string]string{"value": httpsProxy})
		updateConfigMap(t, ctx, client, "no-proxy", map[string]string{"value": noProxy})
		updateConfigMap(t, ctx, client, "ca-cert", map[string]string{"ca.crt": base64.StdEncoding.EncodeToString([]byte(cert))})

		config = &testConfig{
			annotations: annotations,
			labels:      labels,
			cert:        cert,
			httpProxy:   httpProxy,
			httpsProxy:  httpsProxy,
			noProxy:     noProxy,
		}
	})

	return config

}

func setArgs(t *testing.T, ctx context.Context, client kubernetes.Interface) ([]string, []string) {
	args := make([]string, 0)

	annotations := []string{"some-annotation-1", "some-annotation-2"}
	for _, annotation := range annotations {
		args = append(args, fmt.Sprintf("-annotation=%s", annotation))
	}

	labels := []string{"some-label-1", "some-label-2"}
	for _, label := range labels {
		args = append(args, fmt.Sprintf("-label=%s", label))
	}

	original, err := client.AppsV1().Deployments(namespace).Get(ctx, namespace, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	updated := original.DeepCopy()
	updated.Spec.Template.Spec.Containers[0].Args = args

	originalBytes, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}

	updatedBytes, err := json.Marshal(updated)
	if err != nil {
		t.Fatal(err)
	}
	patch, err := jsonpatch.CreateMergePatch(originalBytes, updatedBytes)
	if err != nil {
		t.Fatal(err)
	}

	if string(patch) != "{}" {
		_, err := client.AppsV1().Deployments(namespace).Patch(ctx, namespace, types.StrategicMergePatchType, patch, metav1.PatchOptions{})
		if err != nil {
			t.Fatal(err)
		}
	}
	return annotations, labels
}

func updateConfigMap(t *testing.T, ctx context.Context, client kubernetes.Interface, name string, value map[string]string) {
	original, err := client.CoreV1().ConfigMaps(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}

	update := original.DeepCopy()
	update.Data = value

	_, err = client.CoreV1().ConfigMaps(namespace).Update(ctx, update, metav1.UpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}
}

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
