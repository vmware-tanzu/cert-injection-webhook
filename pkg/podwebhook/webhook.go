package podwebhook

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	// Injection stuff
	kubeclient "knative.dev/pkg/client/injection/kube/client"
	mwhinformer "knative.dev/pkg/client/injection/kube/informers/admissionregistration/v1/mutatingwebhookconfiguration"
	secretinformer "knative.dev/pkg/injection/clients/namespacedkube/informers/core/v1/secret"

	"k8s.io/client-go/tools/cache"
	"knative.dev/pkg/controller"
	"knative.dev/pkg/logging"
	"knative.dev/pkg/system"
	"knative.dev/pkg/webhook"
)

type Webhook struct {
	*reconciler
	*admissionController
}

func NewController(
	ctx context.Context,
	name, path string,
	wc func(context.Context) context.Context,
	labels []string,
	annotations []string,
	envVars []corev1.EnvVar,
	caCertsData, setupCaCertsImage string,
	imagePullSecrets corev1.LocalObjectReference,
) (*controller.Impl, error) {
	client := kubeclient.Get(ctx)
	mwhInformer := mwhinformer.Get(ctx)
	secretInformer := secretinformer.Get(ctx)
	options := webhook.GetOptions(ctx)

	r := NewReconciler(
		name,
		path,
		client,
		mwhInformer.Lister(),
		secretInformer.Lister(),
		options.SecretName,
	)

	ac, err := NewAdmissionController(
		name,
		path,
		wc,
		labels,
		annotations,
		envVars,
		setupCaCertsImage,
		caCertsData,
		imagePullSecrets,
	)
	if err != nil {
		return nil, err
	}

	wh := Webhook{r, ac}

	logger := logging.FromContext(ctx)
	c := controller.NewImpl(wh, logger, "PodWebhook")

	mwhInformer.Informer().AddEventHandler(cache.FilteringResourceEventHandler{
		FilterFunc: controller.FilterWithName(name),
		Handler:    controller.HandleAll(c.Enqueue),
	})

	secretInformer.Informer().AddEventHandler(cache.FilteringResourceEventHandler{
		FilterFunc: controller.FilterWithNameAndNamespace(system.Namespace(), wh.secretName),
		Handler:    controller.HandleAll(c.Enqueue),
	})

	return c, nil
}
