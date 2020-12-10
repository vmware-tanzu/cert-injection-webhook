# Cert Injection Webhook for Kubernetes

## About

The Cert Injection Webhook for Kubernetes extends kubernetes with a webhook that injects
CA certificates and proxy environment variaibles into pods. The webhook uses certificates and
environment variables defined in configmaps and injects them into pods with the desired labels or annotations.

## Contributing

To begin contributing, please read the [contributing](CONTRIBUTING.md) doc.

## Installation and Usage

The Cert Injection Webhook for Kubernetes is deployed using the [Carvel](hhttps://carvel.dev/) tool suite.

### Install

Build the pod-webhook and setup-ca-certs images using the [pack](https://github.com/buildpacks/pack) CLI.

```bash
$ pack build <pod-webhook-image> -e BP_GO_TARGETS="./cmd/pod-webhook" --publish
$ pack build <setup-ca-certs-image> -e BP_GO_TARGETS="./cmd/setup-ca-certs" --publish
```

Use the Carvel tools to install to your cluster.

```bash
$ ytt -f ./deployments/k8s \
      -v pod_webhook_image=<pod-webhook-image> \
      -v setup_ca_certs_image=<setup-ca-certs-image> \
      --data-value-file ca_cert_data=<ca.crt> \
      --data-value-yaml labels="[label-1, label-2]" \
      --data-value-yaml annotations="[annotation-1, annotation-2]" \
      > manifest.yaml
$ kapp deploy -a cert-injection-webhook -f ./manifest.yaml
```

**Note**: You may provide labels, annotations, or both.

### Usage

To have the webhook operate on a Pod, label and annotate the Pod with the labels and annotations you provided during install.

### Uninstall

```bash
kapp delete -a cert-injection-webhook
```
