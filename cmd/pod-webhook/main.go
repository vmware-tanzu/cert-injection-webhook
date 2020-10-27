package main

import (
	"context"
	"encoding/base64"
	"flag"
	"io/ioutil"
	"log"
	"os"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"knative.dev/pkg/configmap"
	"knative.dev/pkg/controller"
	"knative.dev/pkg/injection/sharedmain"
	"knative.dev/pkg/signals"
	"knative.dev/pkg/webhook"
	"knative.dev/pkg/webhook/certificates"

	"github.com/pivotal/cert-injection-webhook/pkg/podwebhook"
)

const (
	defaultWebhookName       = "defaults.webhook.cert-injection.tanzu.vmware.com"
	webhookPath              = "/podwebhook"
	defaultWebhookSecretName = "cert-injection-webhook-tls"
	caCertsFile              = "/run/config_maps/ca_cert/ca.crt"
)

type EnvVars []corev1.EnvVar

func (e *EnvVars) AddEnvIfPresent(env string) {
	val := os.Getenv(env)
	if val == "" {
		return
	}
	*e = append(*e, corev1.EnvVar{Name: env, Value: val})
}

type labelAnnotationFlags []string

func (l *labelAnnotationFlags) Set(value string) error {
	*l = append(*l, value)
	return nil
}

func (l *labelAnnotationFlags) String() string {
	return strings.Join(*l, ", ")
}

var labels, annotations labelAnnotationFlags

func main() {
	flag.Var(&labels, "label", "-label: label to monitor (can be specified multiple times)")
	flag.Var(&annotations, "annotation", "-annotation: annotation to monitor (can be specified multiple times)")
	flag.Parse()

	webhookSecretName := os.Getenv("WEBHOOK_SECRET_NAME")

	if webhookSecretName == "" {
		webhookSecretName = defaultWebhookSecretName
	}

	ctx := webhook.WithOptions(signals.NewContext(), webhook.Options{
		ServiceName: "webhook-server",
		Port:        8443,
		SecretName:  webhookSecretName,
	})

	sharedmain.WebhookMainWithConfig(ctx, "webhook",
		sharedmain.ParseAndGetConfigOrDie(),
		certificates.NewController,
		PodAdmissionController,
	)
}

func PodAdmissionController(ctx context.Context, cmw configmap.Watcher) *controller.Impl {
	envVars := EnvVars{}
	envVars.AddEnvIfPresent("HTTP_PROXY")
	envVars.AddEnvIfPresent("HTTPS_PROXY")
	envVars.AddEnvIfPresent("NO_PROXY")

	caCertsData := ""
	info, err := os.Stat(caCertsFile)
	if err != nil {
		log.Fatal(err)
	}

	if info.Size() > 0 {
		file, err := os.Open(caCertsFile)
		if err != nil {
			log.Fatal(err)
		}
		defer file.Close()

		buf, err := ioutil.ReadAll(base64.NewDecoder(base64.StdEncoding, file))
		if err != nil {
			log.Fatal(err)
		}

		caCertsData = string(buf)
	}

	webhookName := os.Getenv("WEBHOOK_NAME")

	if webhookName == "" {
		webhookName = defaultWebhookName
	}

	systemRegistrySecret := os.Getenv("SYSTEM_REGISTRY_SECRET")

	var imagePullSecrets corev1.LocalObjectReference

	if systemRegistrySecret != "" {
		imagePullSecrets = corev1.LocalObjectReference{Name: systemRegistrySecret}
	}

	c, err := podwebhook.NewController(
		ctx,
		webhookName,
		webhookPath,
		func(ctx context.Context) context.Context {
			return ctx
		},
		labels,
		annotations,
		envVars,
		caCertsData,
		os.Getenv("SETUP_CA_CERTS_IMAGE"),
		imagePullSecrets,
	)
	if err != nil {
		log.Fatal(err)
	}
	return c
}
