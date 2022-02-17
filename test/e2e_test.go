package test

import (
	"context"
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/sclevine/spec"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
)

func TestCertInjectionWebhook(t *testing.T) {
	rand.Seed(time.Now().Unix())

	spec.Run(t, "TestCertInjectionWebhook", testCertInjectionWebhook)
}

func testCertInjectionWebhook(t *testing.T, when spec.G, it spec.S) {
	var (
		client        kubernetes.Interface
		config        *testConfig
		ctx           = context.Background()
		testNamespace = "test"
	)

	it.Before(func() {
		var err error
		client, err = getClient(t)
		require.NoError(t, err)

		config = getTestConfig(t, ctx, client)

		deleteNamespace(t, ctx, client, testNamespace)

		_, err = client.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: testNamespace,
			},
		}, metav1.CreateOptions{})
		require.NoError(t, err)
	})

	when("injecting ca certificates and proxy env", func() {
		it("will match pods by label", func() {
			for i, label := range config.labels {
				podName := fmt.Sprintf("testpod-label-%d", i)
				labels := map[string]string{label: ""}

				createPod(t, ctx, client, testNamespace, podName, labels, map[string]string{})
				pod := getPod(t, ctx, client, testNamespace, podName)
				assertCertInjection(t, config, pod)
				assertProxyEnv(t, config, pod)
				deletePod(t, ctx, client, testNamespace, podName)
			}
		})

		it("will match pods by annotation", func() {
			for i, annotation := range config.annotations {
				podName := fmt.Sprintf("testpod-annotation-%d", i)
				annotations := map[string]string{annotation: podName}

				createPod(t, ctx, client, testNamespace, podName, map[string]string{}, annotations)
				pod := getPod(t, ctx, client, testNamespace, podName)
				assertCertInjection(t, config, pod)
				assertProxyEnv(t, config, pod)
				deletePod(t, ctx, client, testNamespace, podName)
			}
		})
	})
}

func deletePod(t *testing.T, ctx context.Context, client kubernetes.Interface, namespace, name string) {
	err := client.CoreV1().Pods(namespace).Delete(ctx, name, metav1.DeleteOptions{})
	if err != nil {
		t.Log(err)
	}
}

func createPod(t *testing.T, ctx context.Context, client kubernetes.Interface, namespace, name string, labels map[string]string, annotations map[string]string) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   namespace,
			Labels:      labels,
			Annotations: annotations,
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:       "nginx",
					Image:      "nginx:latest",
					Command:    nil,
					Args:       nil,
					WorkingDir: "",
					Ports: []corev1.ContainerPort{
						{
							ContainerPort: 80,
						},
					},
				},
			},
		},
	}

	_, err := client.CoreV1().Pods(namespace).Create(ctx, pod, metav1.CreateOptions{})
	require.NoError(t, err)
}

func deleteNamespace(t *testing.T, ctx context.Context, client kubernetes.Interface, namespace string) {
	err := client.CoreV1().Namespaces().Delete(ctx, namespace, metav1.DeleteOptions{})
	require.True(t, err == nil || k8serrors.IsNotFound(err))
	if k8serrors.IsNotFound(err) {
		return
	}

	var (
		timeout int64 = 120
		closed        = false
	)

	watcher, err := client.CoreV1().Namespaces().Watch(ctx, metav1.ListOptions{
		TimeoutSeconds: &timeout,
	})
	require.NoError(t, err)

	for evt := range watcher.ResultChan() {
		if evt.Type != watch.Deleted {
			continue
		}
		if ns, ok := evt.Object.(*corev1.Namespace); ok {
			if ns.Name == namespace {
				closed = true
				break
			}
		}
	}
	require.True(t, closed)
}

func getPod(t *testing.T, ctx context.Context, client kubernetes.Interface, namespace, name string) *corev1.Pod {
	var (
		pod *corev1.Pod
		err error
	)
	eventually(t, func() bool {
		pod, err = client.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
		if k8serrors.IsNotFound(err) {
			return false
		} else if err != nil {
			t.Error(err)
			return false
		}

		return true
	}, 5*time.Second, 2*time.Minute)

	return pod
}

func assertCertInjection(t *testing.T, config *testConfig, pod *corev1.Pod) {
	var (
		initContainerPresent bool
		volumePresent        bool
	)

	for _, container := range pod.Spec.InitContainers {
		if container.Name == "setup-ca-certs" &&
			container.VolumeMounts[0].Name == "ca-certs" &&
			container.Env[0].Value == config.cert {
			initContainerPresent = true
			break
		}
	}

	for _, volume := range pod.Spec.Volumes {
		if volume.Name == "ca-certs" {
			volumePresent = true
			break
		}
	}

	injected := initContainerPresent && volumePresent
	if !injected {
		t.Errorf("pod should have cert injection: %v", pod)
	}
}

func assertProxyEnv(t *testing.T, config *testConfig, pod *corev1.Pod) {
	expectedEnv := []corev1.EnvVar{
		{
			Name:  "HTTP_PROXY",
			Value: config.httpProxy,
		},
		{
			Name:  "http_proxy",
			Value: config.httpProxy,
		},
		{
			Name:  "HTTPS_PROXY",
			Value: config.httpsProxy,
		},
		{
			Name:  "https_proxy",
			Value: config.httpsProxy,
		},
		{
			Name:  "NO_PROXY",
			Value: config.noProxy,
		},
		{
			Name:  "no_proxy",
			Value: config.noProxy,
		},
	}

	actualEnv := pod.Spec.Containers[0].Env
	assert.Equal(t, expectedEnv, actualEnv)
}
