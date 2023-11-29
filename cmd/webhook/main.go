// Copyright 2020-Present VMware, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/base64"
	"flag"
	"io"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"strconv"

	corev1 "k8s.io/api/core/v1"
	"knative.dev/pkg/configmap"
	"knative.dev/pkg/controller"
	"knative.dev/pkg/injection"
	"knative.dev/pkg/injection/sharedmain"
	"knative.dev/pkg/signals"
	"knative.dev/pkg/webhook"
	"knative.dev/pkg/webhook/certificates"

	"github.com/vmware-tanzu/cert-injection-webhook/pkg/certinjectionwebhook"
)

const (
	defaultWebhookName       = "defaults.webhook.cert-injection.tanzu.vmware.com"
	webhookPath              = "/certinjectionwebhook"
	defaultWebhookSecretName = "cert-injection-webhook-tls"
	defaultWebhookPort       = 8443
	caCertsFile              = "/run/config_maps/ca_cert/ca.crt"
	httpProxyFile            = "/run/config_maps/http_proxy/value"
	httpsProxyFile           = "/run/config_maps/https_proxy/value"
	noProxyFile              = "/run/config_maps/no_proxy/value"
)

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

	webhookPort := defaultWebhookPort
	webhookPortEnv := os.Getenv("WEBHOOK_PORT")
	if parsedWebhookPort, err := strconv.Atoi(webhookPortEnv); err == nil {
		webhookPort = parsedWebhookPort
	}

	ctx := sharedmain.WithHADisabled(webhook.WithOptions(signals.NewContext(), webhook.Options{
		ServiceName: "cert-injection-webhook",
		Port:        webhookPort,
		SecretName:  webhookSecretName,
	}))

	sharedmain.WebhookMainWithConfig(ctx, "webhook",
		injection.ParseAndGetRESTConfigOrDie(),
		certificates.NewController,
		PodAdmissionController,
	)
}

func PodAdmissionController(ctx context.Context, cmw configmap.Watcher) *controller.Impl {
	envVars, err := loadEnvVars()
	if err != nil {
		log.Fatal(err)
	}

	caCertsData, err := readFile(caCertsFile, readBase64)
	if err != nil {
		log.Fatal(err)
	}

	webhookName := os.Getenv("WEBHOOK_NAME")
	if webhookName == "" {
		webhookName = defaultWebhookName
	}

	var imagePullSecrets corev1.LocalObjectReference
	if systemRegistrySecret := os.Getenv("SYSTEM_REGISTRY_SECRET"); systemRegistrySecret != "" {
		imagePullSecrets = corev1.LocalObjectReference{Name: systemRegistrySecret}
	}

	c, err := certinjectionwebhook.NewController(
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

func loadEnvVars() ([]corev1.EnvVar, error) {
	var envVars []corev1.EnvVar

	httpProxy, err := readFile(httpProxyFile, read)
	if err != nil {
		return nil, err
	}
	if httpProxy != "" {
		envVars = append(envVars, corev1.EnvVar{Name: "HTTP_PROXY", Value: httpProxy})
		envVars = append(envVars, corev1.EnvVar{Name: "http_proxy", Value: httpProxy})
	}

	httpsProxy, err := readFile(httpsProxyFile, read)
	if err != nil {
		return nil, err
	}
	if httpsProxy != "" {
		envVars = append(envVars, corev1.EnvVar{Name: "HTTPS_PROXY", Value: httpsProxy})
		envVars = append(envVars, corev1.EnvVar{Name: "https_proxy", Value: httpsProxy})
	}

	noProxy, err := readFile(noProxyFile, read)
	if err != nil {
		return nil, err
	}
	if noProxy != "" {
		envVars = append(envVars, corev1.EnvVar{Name: "NO_PROXY", Value: noProxy})
		envVars = append(envVars, corev1.EnvVar{Name: "no_proxy", Value: noProxy})
	}

	return envVars, nil
}

func readFile(filepath string, read func(reader io.Reader) (string, error)) (string, error) {
	info, err := os.Stat(filepath)
	if err != nil {
		log.Fatal(err)
	}

	if info.Size() == 0 {
		return "", nil
	}

	file, err := os.Open(filepath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	return read(file)
}

func readBase64(reader io.Reader) (string, error) {
	buf, err := ioutil.ReadAll(base64.NewDecoder(base64.StdEncoding, reader))
	if err != nil {
		return "", err
	}

	return string(buf), nil
}

func read(reader io.Reader) (string, error) {
	buf, err := ioutil.ReadAll(reader)
	if err != nil {
		return "", err
	}

	return string(buf), nil
}
