package certs_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"math/rand"
	"testing"
	"time"

	"github.com/sclevine/spec"
	"github.com/stretchr/testify/require"
	"github.com/vmware-tanzu/cert-injection-webhook/pkg/certs"
)

func TestCerts(t *testing.T) {
	spec.Run(t, "Certs", testCerts)
}

func makeCaCert(t *testing.T, rng io.Reader) string {
	t.Helper()
	pKey, err := ecdsa.GenerateKey(elliptic.P256(), rng)
	require.NoError(t, err)

	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{""},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{""},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	ca, err := x509.CreateCertificate(rng, cert, cert, &pKey.PublicKey, pKey)
	require.NoError(t, err)

	pem := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ca,
	})
	return string(pem)
}

func testCerts(t *testing.T, when spec.G, it spec.S) {
	// use insecure prng for certs since this is just a test
	source := rand.NewSource(time.Now().UnixNano())
	prng := rand.New(source)

	when("Splitting", func() {
		it("splits single cert", func() {
			c1 := makeCaCert(t, prng)

			c := certs.Split(c1)
			require.Len(t, c, 1)
			require.Equal(t, c1, c[0])
		})

		it("splits multiple certs", func() {
			c1 := makeCaCert(t, prng)
			c2 := makeCaCert(t, prng)
			c3 := makeCaCert(t, prng)

			c := certs.Split(c1 + "\n" + c2 + "\n" + c3)
			require.Len(t, c, 3)
			require.Equal(t, c1, c[0])
			require.Equal(t, c2, c[1])
			require.Equal(t, c3, c[2])
		})

		it("ignores invalid certs", func() {
			c1 := makeCaCert(t, prng)
			c3 := makeCaCert(t, prng)

			c := certs.Split(c1 + "\n" + "not-a-cert" + "\n" + c3)
			require.Len(t, c, 2)
			require.Equal(t, c1, c[0])
			require.Equal(t, c3, c[1])
		})
	})

	when("Parsing", func() {
		it("parsing no cert", func() {
			envs := []string{
				"SOME-OTHER=ENV",
			}

			certs, err := certs.Parse("CA_CERT_DATA", envs)
			require.NoError(t, err)
			require.Len(t, certs, 0)
		})

		it("parsing single valid cert", func() {
			c1 := makeCaCert(t, prng)
			envs := []string{
				fmt.Sprintf("CA_CERT_DATA_0=%v", c1),
			}

			certs, err := certs.Parse("CA_CERT_DATA", envs)
			require.NoError(t, err)
			require.Len(t, certs, 1)
			require.Equal(t, c1, certs[0])
		})

		it("parsing single invalid cert", func() {
			envs := []string{
				"CA_CERT_DATA_0=not-a-cert",
			}

			_, err := certs.Parse("CA_CERT_DATA", envs)
			require.Error(t, err)
		})

		it("parsing multiple certs", func() {
			c1 := makeCaCert(t, prng)
			c2 := makeCaCert(t, prng)
			c3 := makeCaCert(t, prng)
			envs := []string{
				fmt.Sprintf("CA_CERT_DATA_0=%v", c1),
				fmt.Sprintf("CA_CERT_DATA_1=%v", c2),
				fmt.Sprintf("CA_CERT_DATA_2=%v", c3),
			}

			certs, err := certs.Parse("CA_CERT_DATA", envs)
			require.NoError(t, err)
			require.Len(t, certs, 3)
			require.Equal(t, []string{c1, c2, c3}, certs)
		})

		it("parsing multiple invalid certs", func() {
			c1 := makeCaCert(t, prng)
			c3 := makeCaCert(t, prng)
			envs := []string{
				fmt.Sprintf("CA_CERT_DATA_0=%v", c1),
				fmt.Sprintf("CA_CERT_DATA_1=not-a-cert"),
				fmt.Sprintf("CA_CERT_DATA_2=%v", c3),
			}

			_, err := certs.Parse("CA_CERT_DATA", envs)
			require.Error(t, err)
		})
	})
}
