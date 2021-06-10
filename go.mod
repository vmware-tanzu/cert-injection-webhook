module github.com/pivotal/cert-injection-webhook

go 1.14

require (
	github.com/evanphx/json-patch v4.5.0+incompatible
	github.com/pivotal/kpack v0.1.2
	github.com/pkg/errors v0.9.1
	github.com/sclevine/spec v1.4.0
	github.com/stretchr/testify v1.6.1
	gomodules.xyz/jsonpatch/v3 v3.0.1
	k8s.io/api v0.17.6
	k8s.io/apimachinery v0.17.6
	k8s.io/client-go v11.0.1-0.20190805182717-6502b5e7b1b5+incompatible
	knative.dev/pkg v0.0.0-20200702222342-ea4d6e985ba0
)

replace k8s.io/client-go => k8s.io/client-go v0.17.5
