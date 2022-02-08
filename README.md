# Cert Injection Webhook for Kubernetes

## About

The Cert Injection Webhook for Kubernetes extends kubernetes with a webhook that injects
CA certificates and proxy environment variables into pods. The webhook uses certificates and
environment variables defined in configmaps and injects them into pods with the desired labels or annotations.

## Contributing

To begin contributing, please read the [contributing](CONTRIBUTING.md) doc.

## Installation and Usage

The Cert Injection Webhook for Kubernetes is deployed using the [Carvel](hhttps://carvel.dev/) tool suite.

### Install using kapp
Download the latest release of the cert-injection-webhook.
Use the Carvel tools to install to your cluster.

```bash
$ ytt -f ./config \
      -v ca_cert_data="some cert" \
      --data-value-yaml labels="[label-1, label-2]" \
      --data-value-yaml annotations="[annotation-1, annotation-2]" \
      | kapp deploy -a cert-injection-webhook -f-
```
**Note**: You may provide labels, annotations, or both.

If you would like to build the webhook and setup-ca-certs image yourself, or you would like to use the repo's config directory,
use the [pack](https://github.com/buildpacks/pack) CLI.

```bash
$ pack build <webhook-image> -e BP_GO_TARGETS="./cmd/webhook" --publish
$ pack build <setup-ca-certs-image> -e BP_GO_TARGETS="./cmd/setup-ca-certs" --publish
```

Then, use the Carvel tools to install to your cluster.

```bash
$ ytt -f ./config \
      -v webhook_image=<pod-webhook-image> \
      -v setup_ca_certs_image=<setup-ca-certs-image> \
      -v ca_cert_data="some cert" \
      --data-value-yaml labels="[label-1, label-2]" \
      --data-value-yaml annotations="[annotation-1, annotation-2]" \
      | kapp deploy -a cert-injection-webhook -f-
```

### Usage

To have the webhook operate on a Pod, label or annotate the Pod with the labels and annotations you provided during install.

### Uninstall

```bash
kapp delete -a cert-injection-webhook
```
