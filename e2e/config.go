package e2e

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"math/big"
	"math/rand"
	"os"
	"os/user"
	"path"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	controllerNamespace = "cert-injection-webhook"
	controllerName      = "cert-injection-webhook"
)

var (
	clientSetup   sync.Once
	k8sClient     *kubernetes.Clientset
	clusterConfig *rest.Config
	oldConfigs    map[string]string
	rng           io.Reader
)

func getClient(t *testing.T) (kubernetes.Interface, error) {
	clientSetup.Do(func() {
		kubeconfig := flag.String("kubeconfig", getKubeConfig(), "Path to a kubeconfig. Only required if out-of-cluster.")
		masterURL := flag.String("master", "", "The address of the Kubernetes API server. Overrides any value in kubeconfig. Only required if out-of-cluster.")

		flag.Parse()

		var err error
		clusterConfig, err = clientcmd.BuildConfigFromFlags(*masterURL, *kubeconfig)
		require.NoError(t, err)

		k8sClient, err = kubernetes.NewForConfig(clusterConfig)
		require.NoError(t, err)
	})

	rng = rand.New(rand.NewSource(time.Now().UnixMilli()))
	oldConfigs = make(map[string]string)

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

func generateCA() (*rsa.PrivateKey, *x509.Certificate, error) {
	caKey, err := rsa.GenerateKey(rng, 2048)
	if err != nil {
		return nil, nil, err
	}

	// openssl only uses the first cert found for each common name, so we unique ones
	// https://github.com/openssl/openssl/issues/16304
	id := rand.Int()
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(int64(id)),
		Subject: pkix.Name{
			CommonName:   fmt.Sprintf("%d.sign", id),
			Organization: []string{"signing"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	return caKey, caTemplate, nil
}

func encodeCert(pKey *rsa.PrivateKey, caCert *x509.Certificate) (string, error) {
	bytes, err := x509.CreateCertificate(rng, caCert, caCert, &pKey.PublicKey, pKey)
	if err != nil {
		return "", err
	}

	encoded := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: bytes,
	})
	return string(encoded), nil
}

func generateAndUpdateCerts(ctx context.Context, client kubernetes.Interface) (*rsa.PrivateKey, *x509.Certificate, error) {
	pKey, caCert, err := generateCA()
	if err != nil {
		return nil, nil, err
	}

	caEncoded, err := encodeCert(pKey, caCert)
	if err != nil {
		return nil, nil, err
	}

	err = setCaCerts(ctx, client, caEncoded)
	if err != nil {
		return nil, nil, err
	}

	return pKey, caCert, nil
}

func generateAndUpdateProxies(ctx context.Context, client kubernetes.Interface) (httpProxy string, httpsProxy string, noProxy string, err error) {
	httpProxy = "some-http-proxy"
	err = updateConfigmap(ctx, client, "http-proxy", "value", httpProxy)
	if err != nil {
		return
	}

	httpsProxy = "some-https-proxy"
	err = updateConfigmap(ctx, client, "https-proxy", "value", httpsProxy)
	if err != nil {
		return
	}

	noProxy = "some-no-proxy"
	err = updateConfigmap(ctx, client, "no-proxy", "value", noProxy)
	if err != nil {
		return
	}
	return
}
