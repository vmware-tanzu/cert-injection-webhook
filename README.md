# Cert Injection Webhook for Kubernetes

## About

The Cert Injection Webhook for Kubernetes extends kubernetes with a webhook that injects
CA certificates and proxy environment variables into pods. The webhook uses certificates and
environment variables defined in configmaps and injects them into pods with the desired labels or annotations.

## Contributing

To begin contributing, please read the [contributing](CONTRIBUTING.md) doc.

## Installation and Usage

The Cert Injection Webhook for Kubernetes is deployed using the [Carvel](hhttps://carvel.dev/) tool suite.

### Install using kapp controller
If you would like to install with [Tanzu Community Edition](https://tanzucommunityedition.io/). See [this guide](packaging/README.md)
1. Create an install namespace
   ```bash
   kubectl create namespace cert-injection-webhook-install
   ```

2. Create a service account and role binding for your installation

   ```yaml
   ---
   apiVersion: v1
   kind: ServiceAccount
   metadata:
     name: cert-injection-webhook-install-sa
     namespace: cert-injection-webhook-install
   ---
   apiVersion: rbac.authorization.k8s.io/v1
   kind: ClusterRoleBinding
   metadata:
     name: cert-injection-webhook-install-admin
   roleRef:
     apiGroup: rbac.authorization.k8s.io
     kind: ClusterRole
     name: cluster-admin
   subjects:
   - kind: ServiceAccount
     name: cert-injection-webhook-install-sa
     namespace: cert-injection-webhook-install
   ```

   Apply with:
   ```bash
   kapp deploy -a cert-injection-webhook-sa -n cert-injection-webhook-install -f <PATH-TO-SERVICE-ACCOUNT-YAML>
   ```

3. Create a `cert-injection-webhook-config-values` Secret yaml with the labels or annotations (or both) that you would like to use.
   Any pod that matches one of these labels or annotations will have the provided cert injected.

   ```yaml
   ---
   apiVersion: v1
   kind: Secret
   metadata:
     name: cert-injection-webhook-install-values
     namespace: cert-injection-webhook-install
   stringData:
     values.yml: |
       ---
       labels:
       - kpack.io/build
       annotations:
       - some-annotation
       ca_cert_data: |
         -----BEGIN CERTIFICATE-----
         MIICrDCCAZQCCQDcakcvwbW4UTANBgkqhkiG9w0BAQsFADAYMRYwFAYDVQQDDA1t
         eXdlYnNpdGUuY29tMB4XDTIyMDIxNDE2MjM1OVoXDTMyMDIxMjE2MjM1OVowGDEW
         MBQGA1UEAwwNbXl3ZWJzaXRlLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
         AQoCggEBAMgWkhYr7OPSTuDwGSM5jMQtO5vnqfESPPh829IMTBNXkS0KV6Hi90ka
         T/gIbq0H+QO5Abzh8QDIOWqaTLLp5FedsU1xsGTiKQ+YVKfoQ7T7R/K+adWuJL6H
         i8kgb4ErzhYhDQqsPU6ZglKkTZTL+7fhpsc7ZewASa7TRJiSo51Qye9K1qsjj3Wd
         MB+0qH1vxvN2zs/117qowW/2YH2H++lJSfnEMH4Z67RQ5o56DpeHvE7mLz0LNVu/
         gyM8JXClgsPdr11Iiv17TevWoXSeoWa0ts6MGd/r376dtEZ60wGG+geXcf9szAx1
         GZLEQamRHnVyrGvb7U/AvLaJMnNY8PcCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEA
         bc4XeX7sKvtEHK5tYKJDarP6suArgs7/IpfT2DiRB8JSBYX7rHD6NIB3433JxQfc
         SHD9FBpH9E8aSMDsCWKcuRRI7GeRarqwfblAqflCv85NJaiC9zu+haue7aNMNnwA
         uB+q0urjiKlEOM2OsLqgjXXmx5+nSrdwUhFXmyMsJC2eP4Dm1gJp5tQG2hSONC7w
         dX2wAQp7PYaq+h1ASkDNaKy3ZoeD7yEp3Mhbnh+fu0O06NpnJhUZPhdTtMD3LYPJ
         +iwL43iSAQt05ZK39u23zsdMc+RLFbqQYsULYZS2g/SmcSnw8CC3aer8X6x4lEw7
         FpCpA2Wta8mXHGKqmq0+og==
         -----END CERTIFICATE-----
   ```

   Apply with:
   ```bash
   kapp deploy -a cert-injection-webhook-values -n cert-injection-webhook-install -f <PATH-TO-PACKAGE-SECRET-YAML>
   ```

4. Download the [latest release of the cert-injection-webhook](https://github.com/vmware-tanzu/cert-injection-webhook/releases).

5. Apply the `package.yaml` and `metadata.yaml` from from the release
   ```bash
   ytt -f package.yaml -f metadata.yaml | kapp deploy -a cert-injection-webhook-package -n cert-injection-webhook-install
   ```
   
6. Create a package install

   ```yaml
   ---
   apiVersion: packaging.carvel.dev/v1alpha1
   kind: PackageInstall
   metadata:
      name: cert-injection-webhook-package-install
      namespace: cert-injection-webhook-install 
   spec:
      serviceAccountName: cert-injection-webhook-install-sa
      packageRef:
         refName: cert-injection-webhook.community.tanzu.vmware.com
         versionSelection:
            constraints: <version you would like to deploy>
      values:
      - secretRef:
           name: cert-injection-webhook-install-values
   ```

   Apply with:
   ```bash
   kapp deploy -a cert-injection-webhook-package-install -n cert-injection-webhook-install -f <PATH-TO-PACKAGE-INSTALL-YAML>
   ```

### Install using kapp
Download the latest release of the cert-injection-webhook and get the imagevalues.yaml.
Use the Carvel tools to install to your cluster.

```bash
$ ytt -f ./config \
      -f <PATH-TO-IMAGEVALUES_YAML> \
      -v ca_cert_data="some cert" \
      --data-value-yaml labels="[label-1, label-2]" \
      --data-value-yaml annotations="[annotation-1, annotation-2]" \
      | kapp deploy -a cert-injection-webhook -f-
```
**Note**: You may provide labels, annotations, or both.

If you would like to build the webhook and setup-ca-certs image yourself,
use the [pack](https://github.com/buildpacks/pack) CLI.

```bash
$ pack build <webhook-image> -e BP_GO_TARGETS="./cmd/webhook" --builder paketobuildpacks/builder:base --publish
$ pack build <setup-ca-certs-image> -e BP_GO_TARGETS="./cmd/setup-ca-certs" --builder paketobuildpacks/builder:base --publish
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

#### Injecting certificates into kpack builds

When providing ca_cert_data directly to kpack, that CA Certificate be injected into builds themselves.
If you want kpack builds to have CA Certificates for communicating with a self-signed registry,
make sure the values yaml has a label with `kpack.io/build`. This will match on any build pod that kpack creates.

### Running e2e tests

1. Deploy the cert injection webhook using the following values:

   ```yaml
   ---
   http_proxy: some-http-proxy
   https_proxy: some-https-proxy
   no_proxy: some-no-proxy
   ca_cert_data: some-cert
   labels:
     - some-label-1
     - some-label-2
   annotations:
     - some-annotation-1
     - some-annotation-2
   ```

2. Run the e2e tests

   ```bash
   go test -v ./e2e/...
   ```

### Uninstall
If installed using kapp controller:
```bash
kapp delete -a cert-injection-webhook-package-install -n cert-injection-webhook-install
kapp delete -a cert-injection-webhook-package -n cert-injection-webhook-install
kapp delete -a cert-injection-webhook-values -n cert-injection-webhook-install
 ````

You can also delete the namespace

```bash
kubectl delete namespace cert-injection-webhook-install
```

If installed using kapp:
```bash
kapp delete -a cert-injection-webhook
```
