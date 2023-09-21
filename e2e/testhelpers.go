package e2e

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
)

func eventually(t *testing.T, fun func() bool, interval time.Duration, duration time.Duration) {
	t.Helper()
	endTime := time.Now().Add(duration)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for currentTime := range ticker.C {
		if endTime.Before(currentTime) {
			t.Fatal("time is up")
		}
		if fun() {
			return
		}
	}
}
func opensslTestScriptFor(cert string) string {
	return fmt.Sprintf(`
cd $HOME

cat > test.crt <<EOF
%s
EOF

# openssl has its own separate certs dir ('openssl version -a' -> OPENSSLDIR),
# this is usually updated by 'update-ca-certificates', but since we only save
# the /etc/ssl/certs dir, we need to explicitly pass it in here
openssl verify -CApath /etc/ssl/certs/ test.crt
`, cert)
}

func deletePod(t *testing.T, ctx context.Context, client kubernetes.Interface, namespace, name string) {
	err := client.CoreV1().Pods(namespace).Delete(ctx, name, metav1.DeleteOptions{})
	if err != nil {
		t.Log(err)
	}
}

func createCertTestPod(t *testing.T, ctx context.Context, client kubernetes.Interface, namespace, name string, verificationCert string) {
	t.Helper()

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    map[string]string{"some-label-1": ""},
		},
		Spec: corev1.PodSpec{
			RestartPolicy: corev1.RestartPolicyNever,
			Containers: []corev1.Container{
				{
					Name:       "test",
					Image:      "paketobuildpacks/build-jammy-base",
					Command:    []string{"bash"},
					Args:       []string{"-c", opensslTestScriptFor(verificationCert)},
					WorkingDir: "",
				},
			},
		},
	}

	_, err := client.CoreV1().Pods(namespace).Create(ctx, pod, metav1.CreateOptions{})
	require.NoError(t, err)
}

func createNoopPod(t *testing.T, ctx context.Context, client kubernetes.Interface, namespace, name string, labels map[string]string, annotations map[string]string) {
	t.Helper()

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
					Name:       "test",
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

func getLogs(t *testing.T, ctx context.Context, client kubernetes.Interface, namespace, name, container string) string {
	t.Helper()
	req := client.CoreV1().Pods(namespace).GetLogs(name, &corev1.PodLogOptions{Container: container})
	logReader, err := req.Stream(ctx)
	require.NoError(t, err)
	defer logReader.Close()

	b, err := io.ReadAll(logReader)
	require.NoError(t, err)
	return string(b)
}

func deleteNamespace(t *testing.T, ctx context.Context, client kubernetes.Interface, namespace string) {
	t.Helper()

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
	t.Helper()

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

func parseConfigmapName(ctx context.Context, client kubernetes.Interface, name string) (string, error) {
	deployment, err := client.AppsV1().Deployments(controllerNamespace).Get(ctx, controllerName, metav1.GetOptions{})
	if err != nil {
		return "", err
	}

	configmapName := ""
	for _, v := range deployment.Spec.Template.Spec.Volumes {
		if v.Name == name {
			configmapName = v.ConfigMap.Name
			break
		}
	}

	if configmapName == "" {
		return "", fmt.Errorf("no configmap found")
	}
	return configmapName, nil
}

func updateConfigmap(ctx context.Context, client kubernetes.Interface, name, key, value string) error {
	configmapName, err := parseConfigmapName(ctx, client, name)
	if err != nil {
		return err
	}

	config, err := client.CoreV1().ConfigMaps(controllerNamespace).Get(ctx, configmapName, metav1.GetOptions{})
	if err != nil {
		return err
	}

	oldConfigs[name] = config.Data[key]

	newConfig := config.DeepCopy()
	newConfig.Data[key] = value

	_, err = client.CoreV1().ConfigMaps(controllerNamespace).Update(ctx, newConfig, metav1.UpdateOptions{})
	return err
}

func setCaCerts(ctx context.Context, client kubernetes.Interface, certs string) error {
	encoded := &strings.Builder{}
	_, err := io.WriteString(base64.NewEncoder(base64.StdEncoding, encoded), certs)
	if err != nil {
		return err
	}

	return updateConfigmap(ctx, client, "webhook-ca-cert", "ca.crt", encoded.String())
}

func restoreCaCerts(ctx context.Context, client kubernetes.Interface) error {
	return updateConfigmap(ctx, client, "webhook-ca-cert", "ca.crt", oldConfigs["ca-cert"])
}

func restoreProxies(ctx context.Context, client kubernetes.Interface) error {
	err := updateConfigmap(ctx, client, "http-proxy", "value", oldConfigs["http-proxy"])
	if err != nil {
		return err
	}
	err = updateConfigmap(ctx, client, "https-proxy", "value", oldConfigs["https-proxy"])
	if err != nil {
		return err
	}

	err = updateConfigmap(ctx, client, "no-proxy", "value", oldConfigs["no-proxy"])
	if err != nil {
		return err
	}
	return nil
}

func restartController(t *testing.T, ctx context.Context, client kubernetes.Interface) error {
	err := client.CoreV1().Pods(controllerNamespace).DeleteCollection(ctx, metav1.DeleteOptions{}, metav1.ListOptions{
		LabelSelector: "app=cert-injection-webhook",
	})
	require.NoError(t, err)

	eventually(t, func() bool {
		list, err := client.CoreV1().Pods(controllerNamespace).List(ctx, metav1.ListOptions{
			LabelSelector: "app=cert-injection-webhook",
		})
		require.NoError(t, err)

		return len(list.Items) == 1
	}, 5*time.Second, 2*time.Minute)

	return nil
}

func generateCert(caPrivateKey *rsa.PrivateKey, caCert *x509.Certificate) (string, error) {
	privateKey, err := rsa.GenerateKey(rng, 2048)
	if err != nil {
		return "", err
	}

	cert := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName:   "test",
			Organization: []string{"testing"},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(10, 0, 0),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}
	certBytes, err := x509.CreateCertificate(rng, cert, caCert, &privateKey.PublicKey, caPrivateKey)
	if err != nil {
		return "", err
	}

	encoded := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	return string(encoded), nil
}
