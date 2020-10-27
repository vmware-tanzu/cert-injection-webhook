package podwebhook_test

import (
	"testing"

	"github.com/pivotal/kpack/pkg/reconciler/testhelpers"
	"github.com/sclevine/spec"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	clientgotesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/record"
	"knative.dev/pkg/controller"
	rtesting "knative.dev/pkg/reconciler/testing"
	"knative.dev/pkg/system"
	certresources "knative.dev/pkg/webhook/certificates/resources"
	wtesting "knative.dev/pkg/webhook/testing"

	"github.com/pivotal/cert-injection-webhook/pkg/podwebhook"
)

func TestReconciler(t *testing.T) {
	spec.Run(t, "Reconciler", testReconciler)
}

func testReconciler(t *testing.T, when spec.G, it spec.S) {
	const (
		name         = "some-webhook"
		caSecretName = "some-secret"
	)
	var (
		path     = "/some-path"
		certData = []byte("some-cert")
	)

	when("#Reconcile", func() {
		rt := testhelpers.ReconcilerTester(t,
			func(t *testing.T, row *rtesting.TableRow) (reconciler controller.Reconciler, lists rtesting.ActionRecorderList, list rtesting.EventList) {
				listers := wtesting.NewListers(row.Objects)
				secretLister := listers.GetSecretLister()
				mwhcLister := listers.GetMutatingWebhookConfigurationLister()

				k8sfakeClient := k8sfake.NewSimpleClientset(listers.GetKubeObjects()...)

				eventRecorder := record.NewFakeRecorder(10)
				actionRecorderList := rtesting.ActionRecorderList{k8sfakeClient}
				eventList := rtesting.EventList{Recorder: eventRecorder}

				r := podwebhook.NewReconciler(
					name,
					path,
					k8sfakeClient,
					mwhcLister,
					secretLister,
					caSecretName,
				)

				return r, actionRecorderList, eventList
			})

		it("Updates the webhook with the ca cert secret", func() {
			caSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      caSecretName,
					Namespace: system.Namespace(),
				},
				Data: map[string][]byte{
					certresources.CACert: certData,
				},
			}

			webhookConfig := &admissionregistrationv1.MutatingWebhookConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Name: name,
				},
				Webhooks: []admissionregistrationv1.MutatingWebhook{
					{
						Name: name,
						ClientConfig: admissionregistrationv1.WebhookClientConfig{
							Service: &admissionregistrationv1.ServiceReference{},
						},
					},
				},
			}

			rt.Test(rtesting.TableRow{
				Key: "some-namespace/pod-webhook",
				Objects: []runtime.Object{
					caSecret,
					webhookConfig,
				},
				WantErr: false,
				WantUpdates: []clientgotesting.UpdateActionImpl{
					{
						Object: &admissionregistrationv1.MutatingWebhookConfiguration{
							ObjectMeta: metav1.ObjectMeta{
								Name: name,
							},
							Webhooks: []admissionregistrationv1.MutatingWebhook{
								{
									Name: name,
									ClientConfig: admissionregistrationv1.WebhookClientConfig{
										Service: &admissionregistrationv1.ServiceReference{
											Path: &path,
										},
										CABundle: certData,
									},
								},
							},
						},
					},
				},
			})
		})
	})
}
