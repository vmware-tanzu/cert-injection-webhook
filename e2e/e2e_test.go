package e2e

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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
)

func TestCertInjectionWebhook(t *testing.T) {
	rand.Seed(time.Now().Unix())

	spec.Run(t, "TestCertInjectionWebhook", testCertInjectionWebhook)
}

func testCertInjectionWebhook(t *testing.T, when spec.G, it spec.S) {
	var (
		client kubernetes.Interface
		ctx    = context.Background()

		testNamespace = "test"
		podName       string

		waitForPodTermination = func() {
			eventually(t, func() bool {
				pod := getPod(t, ctx, client, testNamespace, podName)
				return pod.Status.ContainerStatuses[0].State.Terminated != nil
			}, 5*time.Second, 2*time.Minute)
		}
	)

	it.Before(func() {
		var err error
		client, err = getClient(t)
		require.NoError(t, err)

		deleteNamespace(t, ctx, client, testNamespace)

		_, err = client.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: testNamespace,
			},
		}, metav1.CreateOptions{})
		require.NoError(t, err)
	})

	when("ensuring containers ar injected", func() {
		it.Before(func() {
			_, _, err := generateAndUpdateCerts(ctx, client)
			require.NoError(t, err)
			require.NoError(t, restartController(t, ctx, client))
		})

		it.After(func() {
			deletePod(t, ctx, client, testNamespace, podName)
			require.NoError(t, restoreProxies(ctx, client))
			require.NoError(t, restartController(t, ctx, client))
		})

		it("will match pods that have any label the webhook is matching on", func() {
			for i, label := range []string{"some-label-1", "some-label-2"} {
				podName = fmt.Sprintf("testpod-label-%d", i)
				labels := map[string]string{label: ""}

				createNoopPod(t, ctx, client, testNamespace, podName, labels, map[string]string{})
				pod := getPod(t, ctx, client, testNamespace, podName)
				require.True(t, hasInjectedContainer(t, pod), "should have cert injection container")
			}
		})

		it("will match pods that have any annotation the webhook is matching on", func() {
			for i, annotation := range []string{"some-annotation-1", "some-annotation-2"} {
				podName = fmt.Sprintf("testpod-annotation-%d", i)
				annotations := map[string]string{annotation: podName}

				createNoopPod(t, ctx, client, testNamespace, podName, map[string]string{}, annotations)
				pod := getPod(t, ctx, client, testNamespace, podName)
				require.True(t, hasInjectedContainer(t, pod), "should have cert injection container")
			}
		})

		it("doesn't match pods that don't have any annotation or label the webhook is matching on", func() {
			podName = fmt.Sprintf("testpod-no-match")
			labels := map[string]string{"some-label-3": ""}
			annotations := map[string]string{"some-annotation-3": podName}

			createNoopPod(t, ctx, client, testNamespace, podName, labels, annotations)
			pod := getPod(t, ctx, client, testNamespace, podName)
			require.False(t, hasInjectedContainer(t, pod), "should not have cert injection container")
		})
	})

	when("ensuring injected containers are correct", func() {
		it.After(func() {
			deletePod(t, ctx, client, testNamespace, podName)
			require.NoError(t, restoreProxies(ctx, client))
			require.NoError(t, restoreCaCerts(ctx, client))
			require.NoError(t, restartController(t, ctx, client))
		})

		podLogFormat := `setup-ca-cert container logs:
%s
test container logs:
%s`

		it("injects proxy envs", func() {
			http, https, no, err := generateAndUpdateProxies(ctx, client)
			require.NoError(t, err)

			require.NoError(t, restartController(t, ctx, client))

			podName = "testpod-proxy-envs"
			createNoopPod(t, ctx, client, testNamespace, podName, map[string]string{"some-label-1": ""}, map[string]string{})
			pod := getPod(t, ctx, client, testNamespace, podName)
			expectedEnv := []corev1.EnvVar{
				{Name: "HTTP_PROXY", Value: http},
				{Name: "http_proxy", Value: http},
				{Name: "HTTPS_PROXY", Value: https},
				{Name: "https_proxy", Value: https},
				{Name: "NO_PROXY", Value: no},
				{Name: "no_proxy", Value: no},
			}
			actualEnv := pod.Spec.Containers[0].Env
			assert.Equal(t, expectedEnv, actualEnv)
		})

		it("injects certs", func() {
			caKey, caCert, err := generateAndUpdateCerts(ctx, client)
			require.NoError(t, err)

			require.NoError(t, restartController(t, ctx, client))

			testingCert, err := generateCert(caKey, caCert)
			require.NoError(t, err)

			podName = "testpod-verify-cert"
			createCertTestPod(t, ctx, client,
				testNamespace, podName,
				testingCert,
			)

			waitForPodTermination()
			pod := getPod(t, ctx, client, testNamespace, podName)
			require.Len(t, pod.Status.ContainerStatuses, 1)

			setupLogs := getLogs(t, ctx, client, testNamespace, pod.Name, "setup-ca-certs")
			podLogs := getLogs(t, ctx, client, testNamespace, pod.Name, "test")
			require.Equal(t, int32(0), pod.Status.ContainerStatuses[0].State.Terminated.ExitCode,
				podLogFormat, setupLogs, podLogs,
			)
		})

		it("can handle super long certs", func() {
			// k8s configmaps have a size limit of 1mb, 550 certs should be just shy of that.
			certChain := ""
			for i := 0; i < 549; i++ {
				// because openssl rehash skips duplicates, we're currently generating
				// unique keys+certs at the cost of increased time (even when using prng
				// instead of cryptographically secure rng)
				k, c, err := generateCA()
				require.NoError(t, err)
				p, err := encodeCert(k, c)
				require.NoError(t, err)

				certChain += fmt.Sprintln(p)
			}

			// actual key/cert that will be used in test
			key, cert, err := generateCA()
			require.NoError(t, err)
			pem, err := encodeCert(key, cert)
			require.NoError(t, err)

			certChain += fmt.Sprintln(pem)

			require.NoError(t, setCaCerts(ctx, client, certChain))
			require.NoError(t, restartController(t, ctx, client))

			testingCert, err := generateCert(key, cert)
			require.NoError(t, err)

			podName = "testpod-many-certs"
			createCertTestPod(t, ctx, client,
				testNamespace, podName,
				testingCert,
			)

			waitForPodTermination()
			pod := getPod(t, ctx, client, testNamespace, podName)
			require.Len(t, pod.Status.ContainerStatuses, 1)

			setupLogs := getLogs(t, ctx, client, testNamespace, pod.Name, "setup-ca-certs")
			podLogs := getLogs(t, ctx, client, testNamespace, pod.Name, "test")
			require.Equal(t, int32(0), pod.Status.ContainerStatuses[0].State.Terminated.ExitCode,
				podLogFormat, setupLogs, podLogs,
			)
		})
	})
}

func hasInjectedContainer(t *testing.T, pod *corev1.Pod) bool {
	var (
		initContainerPresent bool
		volumePresent        bool
	)

	for _, container := range pod.Spec.InitContainers {
		if container.Name == "setup-ca-certs" && container.VolumeMounts[0].Name == "ca-certs" {
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

	return initContainerPresent && volumePresent
}
