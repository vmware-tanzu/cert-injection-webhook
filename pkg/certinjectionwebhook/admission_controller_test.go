// Copyright 2020-Present VMware, Inc.
// SPDX-License-Identifier: Apache-2.0

package certinjectionwebhook_test

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	jp "github.com/evanphx/json-patch/v5"
	"github.com/sclevine/spec"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vmware-tanzu/cert-injection-webhook/pkg/certinjectionwebhook"
	"gomodules.xyz/jsonpatch/v3"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	wtesting "knative.dev/pkg/webhook/testing"
)

func TestPodAdmissionController(t *testing.T) {
	spec.Run(t, "Pod Admission Controller", testPodAdmissionController)
}

func testPodAdmissionController(t *testing.T, when spec.G, it spec.S) {
	const (
		name = "some-webhook"
		path = "/some-path"
	)

	when("#NewAdmissionController", func() {
		it("returns an error if there is not at least one label or annotation", func() {
			_, err := certinjectionwebhook.NewAdmissionController(
				"",
				"",
				nil,
				[]string{},
				[]string{},
				nil,
				"",
				"",
				corev1.LocalObjectReference{},
			)
			require.Errorf(t, err, "at least one label or annotation required")

			_, err = certinjectionwebhook.NewAdmissionController(
				"",
				"",
				nil,
				[]string{"label"},
				[]string{},
				nil,
				"",
				"",
				corev1.LocalObjectReference{},
			)
			require.NoError(t, err)

			_, err = certinjectionwebhook.NewAdmissionController(
				"",
				"",
				nil,
				[]string{},
				[]string{"annotation"},
				nil,
				"",
				"",
				corev1.LocalObjectReference{},
			)
			require.NoError(t, err)
		})
	})

	when("#Admit", func() {
		const (
			label      = "some/label"
			annotation = "some.annotation"

			setupCACertsImage = "some-ca-certs-image"
			caCertsData       = "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----"
		)

		envVars := []corev1.EnvVar{
			{
				Name:  "HTTP_PROXY",
				Value: "http://my.proxy.com",
			},
			{
				Name:  "NO_PROXY",
				Value: "http://my.local.com",
			},
		}

		testPod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name: "object-meta",
			},
			Spec: corev1.PodSpec{
				InitContainers: []corev1.Container{
					{
						Name:  "init-container-without-env",
						Image: "image",
						Env:   nil,
					},
					{
						Name:  "init-container-with-env",
						Image: "image",
						Env: []corev1.EnvVar{
							{
								Name:  "EXISTING",
								Value: "VALUE",
							},
						},
					},
				},
				Containers: []corev1.Container{
					{
						Name:  "container-without-env",
						Image: "image",
						Env:   nil,
					},
					{
						Name:  "container-with-env",
						Image: "image",
						Env: []corev1.EnvVar{
							{
								Name:  "EXISTING",
								Value: "VALUE",
							},
						},
					},
				},
			},
		}

		ctx := context.TODO()

		it("sets the env vars on all containers on the pods that are labelled", func() {
			ac, err := certinjectionwebhook.NewAdmissionController(
				name,
				path,
				func(ctx context.Context) context.Context { return ctx },
				[]string{label},
				[]string{},
				envVars,
				"",
				"",
				corev1.LocalObjectReference{},
			)
			require.NoError(t, err)

			testPod.Labels = map[string]string{
				label: "some value",
			}

			bytes, err := json.Marshal(testPod)
			require.NoError(t, err)

			admissionRequest := &admissionv1.AdmissionRequest{
				Name: "testAdmissionRequest",
				Object: runtime.RawExtension{
					Raw: bytes,
				},
				Operation: admissionv1.Create,
				Resource:  metav1.GroupVersionResource{Version: "v1", Resource: "pods"},
			}

			response := ac.Admit(ctx, admissionRequest)
			wtesting.ExpectAllowed(t, response)

			patch, err := jp.DecodePatch(response.Patch)
			require.NoError(t, err)

			buf, err := patch.Apply(bytes)
			require.NoError(t, err)

			var actualPod corev1.Pod
			err = json.Unmarshal(buf, &actualPod)
			require.NoError(t, err)

			expectedPod := corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name: "object-meta",
					Labels: map[string]string{
						label: "some value",
					},
				},
				Spec: corev1.PodSpec{
					InitContainers: []corev1.Container{
						{
							Name:  "init-container-without-env",
							Image: "image",
							Env: []corev1.EnvVar{
								{
									Name:  "HTTP_PROXY",
									Value: "http://my.proxy.com",
								},
								{
									Name:  "NO_PROXY",
									Value: "http://my.local.com",
								},
							},
						},
						{
							Name:  "init-container-with-env",
							Image: "image",
							Env: []corev1.EnvVar{
								{
									Name:  "EXISTING",
									Value: "VALUE",
								},
								{
									Name:  "HTTP_PROXY",
									Value: "http://my.proxy.com",
								},
								{
									Name:  "NO_PROXY",
									Value: "http://my.local.com",
								},
							},
						},
					},
					Containers: []corev1.Container{
						{
							Name:  "container-without-env",
							Image: "image",
							Env: []corev1.EnvVar{
								{
									Name:  "HTTP_PROXY",
									Value: "http://my.proxy.com",
								},
								{
									Name:  "NO_PROXY",
									Value: "http://my.local.com",
								},
							},
						},
						{
							Name:  "container-with-env",
							Image: "image",
							Env: []corev1.EnvVar{
								{
									Name:  "EXISTING",
									Value: "VALUE",
								},
								{
									Name:  "HTTP_PROXY",
									Value: "http://my.proxy.com",
								},
								{
									Name:  "NO_PROXY",
									Value: "http://my.local.com",
								},
							},
						},
					},
				},
			}
			require.Equal(t, expectedPod, actualPod)
		})

		it("sets the env vars on all containers on the pods that are annotated", func() {
			testPod.Annotations = map[string]string{
				annotation: "some value",
			}

			bytes, err := json.Marshal(testPod)
			require.NoError(t, err)

			admissionRequest := &admissionv1.AdmissionRequest{
				Name: "testAdmissionRequest",
				Object: runtime.RawExtension{
					Raw: bytes,
				},
				Operation: admissionv1.Create,
				Resource:  metav1.GroupVersionResource{Version: "v1", Resource: "pods"},
			}

			ac, err := certinjectionwebhook.NewAdmissionController(
				name,
				path,
				func(ctx context.Context) context.Context { return ctx },
				[]string{},
				[]string{annotation},
				envVars,
				"",
				"",
				corev1.LocalObjectReference{},
			)
			require.NoError(t, err)

			response := ac.Admit(ctx, admissionRequest)
			wtesting.ExpectAllowed(t, response)

			patch, err := jp.DecodePatch(response.Patch)
			require.NoError(t, err)

			buf, err := patch.Apply(bytes)
			require.NoError(t, err)

			var actualPod corev1.Pod
			err = json.Unmarshal(buf, &actualPod)
			require.NoError(t, err)

			expectedPod := corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name: "object-meta",
					Annotations: map[string]string{
						annotation: "some value",
					},
				},
				Spec: corev1.PodSpec{
					InitContainers: []corev1.Container{
						{
							Name:  "init-container-without-env",
							Image: "image",
							Env: []corev1.EnvVar{
								{
									Name:  "HTTP_PROXY",
									Value: "http://my.proxy.com",
								},
								{
									Name:  "NO_PROXY",
									Value: "http://my.local.com",
								},
							},
						},
						{
							Name:  "init-container-with-env",
							Image: "image",
							Env: []corev1.EnvVar{
								{
									Name:  "EXISTING",
									Value: "VALUE",
								},
								{
									Name:  "HTTP_PROXY",
									Value: "http://my.proxy.com",
								},
								{
									Name:  "NO_PROXY",
									Value: "http://my.local.com",
								},
							},
						},
					},
					Containers: []corev1.Container{
						{
							Name:  "container-without-env",
							Image: "image",
							Env: []corev1.EnvVar{
								{
									Name:  "HTTP_PROXY",
									Value: "http://my.proxy.com",
								},
								{
									Name:  "NO_PROXY",
									Value: "http://my.local.com",
								},
							},
						},
						{
							Name:  "container-with-env",
							Image: "image",
							Env: []corev1.EnvVar{
								{
									Name:  "EXISTING",
									Value: "VALUE",
								},
								{
									Name:  "HTTP_PROXY",
									Value: "http://my.proxy.com",
								},
								{
									Name:  "NO_PROXY",
									Value: "http://my.local.com",
								},
							},
						},
					},
				},
			}
			require.Equal(t, expectedPod, actualPod)
		})

		it("sets the ca certs on all containers on the pods that are labelled", func() {
			testPod.Labels = map[string]string{
				label: "some value",
			}

			bytes, err := json.Marshal(testPod)
			require.NoError(t, err)

			admissionRequest := &admissionv1.AdmissionRequest{
				Name: "testAdmissionRequest",
				Object: runtime.RawExtension{
					Raw: bytes,
				},
				Operation: admissionv1.Create,
				Resource:  metav1.GroupVersionResource{Version: "v1", Resource: "pods"},
			}

			ac, err := certinjectionwebhook.NewAdmissionController(
				name,
				path,
				func(ctx context.Context) context.Context { return ctx },
				[]string{label},
				[]string{},
				[]corev1.EnvVar{},
				setupCACertsImage,
				caCertsData,
				corev1.LocalObjectReference{},
			)
			require.NoError(t, err)

			response := ac.Admit(ctx, admissionRequest)
			wtesting.ExpectAllowed(t, response)

			var actualPatch []jsonpatch.JsonPatchOperation
			err = json.Unmarshal(response.Patch, &actualPatch)
			require.NoError(t, err)

			expectedJSON := `[
  {
    "op": "add",
    "path": "/spec/volumes",
    "value": [
      {
        "emptyDir": {},
        "name": "ca-certs"
      }
    ]
  },
  {
    "op": "add",
    "path": "/spec/initContainers/2",
    "value": {
      "env": [
        {
          "name": "EXISTING",
          "value": "VALUE"
        }
      ],
      "image": "image",
      "name": "init-container-with-env",
      "resources": {},
      "volumeMounts": [
        {
          "mountPath": "/etc/ssl/certs",
          "name": "ca-certs",
          "readOnly": true
        }
      ]
    }
  },
  {
    "op": "add",
    "path": "/spec/initContainers/0/env",
    "value": [
      {
        "name": "CA_CERTS_DATA_0",
        "value": "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n"
      }
    ]
  },
  {
    "op": "add",
    "path": "/spec/initContainers/0/volumeMounts",
    "value": [
      {
        "mountPath": "/workspace",
        "name": "ca-certs"
      }
    ]
  },
  {
    "op": "add",
    "path": "/spec/initContainers/0/imagePullPolicy",
    "value": "IfNotPresent"
  },
  {
    "op": "add",
    "path": "/spec/initContainers/0/securityContext",
    "value": {
	    "allowPrivilegeEscalation": false,
	    "capabilities": {"drop": ["ALL"]},
	    "privileged": false,
	    "runAsNonRoot": true,
	    "seccompProfile": {"type": "RuntimeDefault"}
    }
  },
  {
    "op": "replace",
    "path": "/spec/initContainers/0/name",
    "value": "setup-ca-certs"
  },
  {
    "op": "replace",
    "path": "/spec/initContainers/0/image",
    "value": "some-ca-certs-image"
  },
  {
    "op": "add",
    "path": "/spec/initContainers/0/workingDir",
    "value": "/workspace"
  },
  {
    "op": "replace",
    "path": "/spec/initContainers/1/name",
    "value": "init-container-without-env"
  },
  {
    "op": "add",
    "path": "/spec/initContainers/1/volumeMounts",
    "value": [
      {
        "mountPath": "/etc/ssl/certs",
        "name": "ca-certs",
        "readOnly": true
      }
    ]
  },
  {
    "op": "remove",
    "path": "/spec/initContainers/1/env"
  },
  {
    "op": "add",
    "path": "/spec/containers/0/volumeMounts",
    "value": [
      {
        "mountPath": "/etc/ssl/certs",
        "name": "ca-certs",
        "readOnly": true
      }
    ]
  },
  {
    "op": "add",
    "path": "/spec/containers/1/volumeMounts",
    "value": [
      {
        "mountPath": "/etc/ssl/certs",
        "name": "ca-certs",
        "readOnly": true
      }
    ]
  }
]`
			var expectedPatch []jsonpatch.JsonPatchOperation
			err = json.Unmarshal([]byte(expectedJSON), &expectedPatch)
			require.NoError(t, err)

			assert.ElementsMatch(t, expectedPatch, actualPatch)
		})

		it("does not inject ca certs on windows pods", func() {
			testPod.Labels = map[string]string{
				label: "some value",
			}
			selectorMap := map[string]string{"kubernetes.io/os": "windows"}

			testPod.Spec.NodeSelector = selectorMap

			bytes, err := json.Marshal(testPod)
			require.NoError(t, err)

			admissionRequest := &admissionv1.AdmissionRequest{
				Name: "testAdmissionRequest",
				Object: runtime.RawExtension{
					Raw: bytes,
				},
				Operation: admissionv1.Create,
				Resource:  metav1.GroupVersionResource{Version: "v1", Resource: "pods"},
			}

			ac, err := certinjectionwebhook.NewAdmissionController(
				name,
				path,
				func(ctx context.Context) context.Context { return ctx },
				[]string{label},
				[]string{},
				[]corev1.EnvVar{},
				setupCACertsImage,
				caCertsData,
				corev1.LocalObjectReference{},
			)
			require.NoError(t, err)

			response := ac.Admit(ctx, admissionRequest)
			wtesting.ExpectAllowed(t, response)

			require.Nil(t, response.Patch)
			require.NoError(t, err)

			require.Equal(t, true, response.Allowed)

		})

		it("sets the ca certs on all containers on the pods that are annotated", func() {
			testPod.Annotations = map[string]string{
				annotation: "some value",
			}

			bytes, err := json.Marshal(testPod)
			require.NoError(t, err)

			admissionRequest := &admissionv1.AdmissionRequest{
				Name: "testAdmissionRequest",
				Object: runtime.RawExtension{
					Raw: bytes,
				},
				Operation: admissionv1.Create,
				Resource:  metav1.GroupVersionResource{Version: "v1", Resource: "pods"},
			}

			ac, err := certinjectionwebhook.NewAdmissionController(
				name,
				path,
				func(ctx context.Context) context.Context { return ctx },
				[]string{},
				[]string{annotation},
				[]corev1.EnvVar{},
				setupCACertsImage,
				caCertsData,
				corev1.LocalObjectReference{},
			)
			require.NoError(t, err)

			response := ac.Admit(ctx, admissionRequest)
			wtesting.ExpectAllowed(t, response)

			var actualPatch []jsonpatch.JsonPatchOperation
			err = json.Unmarshal(response.Patch, &actualPatch)
			require.NoError(t, err)

			expectedJSON := `[
  {
    "op": "add",
    "path": "/spec/volumes",
    "value": [
      {
        "emptyDir": {},
        "name": "ca-certs"
      }
    ]
  },
  {
    "op": "add",
    "path": "/spec/initContainers/2",
    "value": {
      "env": [
        {
          "name": "EXISTING",
          "value": "VALUE"
        }
      ],
      "image": "image",
      "name": "init-container-with-env",
      "resources": {},
      "volumeMounts": [
        {
          "mountPath": "/etc/ssl/certs",
          "name": "ca-certs",
          "readOnly": true
        }
      ]
    }
  },
  {
    "op": "add",
    "path": "/spec/initContainers/0/env",
    "value": [
      {
        "name": "CA_CERTS_DATA_0",
        "value": "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n"
      }
    ]
  },
  {
    "op": "add",
    "path": "/spec/initContainers/0/volumeMounts",
    "value": [
      {
        "mountPath": "/workspace",
        "name": "ca-certs"
      }
    ]
  },
  {
    "op": "add",
    "path": "/spec/initContainers/0/imagePullPolicy",
    "value": "IfNotPresent"
  },
  {
    "op": "add",
    "path": "/spec/initContainers/0/securityContext",
    "value": {
	    "allowPrivilegeEscalation": false,
	    "capabilities": {"drop": ["ALL"]},
	    "privileged": false,
	    "runAsNonRoot": true,
	    "seccompProfile": {"type": "RuntimeDefault"}
    }
  },
  {
    "op": "replace",
    "path": "/spec/initContainers/0/name",
    "value": "setup-ca-certs"
  },
  {
    "op": "replace",
    "path": "/spec/initContainers/0/image",
    "value": "some-ca-certs-image"
  },
  {
    "op": "add",
    "path": "/spec/initContainers/0/workingDir",
    "value": "/workspace"
  },
  {
    "op": "add",
    "path": "/spec/initContainers/1/volumeMounts",
    "value": [
      {
        "mountPath": "/etc/ssl/certs",
        "name": "ca-certs",
        "readOnly": true
      }
    ]
  },
  {
    "op": "replace",
    "path": "/spec/initContainers/1/name",
    "value": "init-container-without-env"
  },
  {
    "op": "remove",
    "path": "/spec/initContainers/1/env"
  },
  {
    "op": "add",
    "path": "/spec/containers/0/volumeMounts",
    "value": [
      {
        "mountPath": "/etc/ssl/certs",
        "name": "ca-certs",
        "readOnly": true
      }
    ]
  },
  {
    "op": "add",
    "path": "/spec/containers/1/volumeMounts",
    "value": [
      {
        "mountPath": "/etc/ssl/certs",
        "name": "ca-certs",
        "readOnly": true
      }
    ]
  }
]
`

			var expectedPatch []jsonpatch.JsonPatchOperation
			err = json.Unmarshal([]byte(expectedJSON), &expectedPatch)
			require.NoError(t, err)

			assert.ElementsMatch(t, expectedPatch, actualPatch)
		})

		it("applies both env and certs changes for custom labels", func() {
			testPod.Labels = map[string]string{
				label: "some value",
			}

			bytes, err := json.Marshal(testPod)
			require.NoError(t, err)

			admissionRequest := &admissionv1.AdmissionRequest{
				Name: "testAdmissionRequest",
				Object: runtime.RawExtension{
					Raw: bytes,
				},
				Operation: admissionv1.Create,
				Resource:  metav1.GroupVersionResource{Version: "v1", Resource: "pods"},
			}

			ac, err := certinjectionwebhook.NewAdmissionController(
				name,
				path,
				func(ctx context.Context) context.Context { return ctx },
				[]string{label},
				[]string{},
				envVars,
				setupCACertsImage,
				caCertsData,
				corev1.LocalObjectReference{},
			)
			require.NoError(t, err)

			response := ac.Admit(ctx, admissionRequest)
			wtesting.ExpectAllowed(t, response)

			var actualPatch []jsonpatch.JsonPatchOperation
			err = json.Unmarshal(response.Patch, &actualPatch)
			require.NoError(t, err)

			expectedJSON := `[
  {
    "op": "add",
    "path": "/spec/volumes",
    "value": [
      {
        "emptyDir": {},
        "name": "ca-certs"
      }
    ]
  },
  {
    "op": "add",
    "path": "/spec/initContainers/2",
    "value": {
      "env": [
        {
          "name": "EXISTING",
          "value": "VALUE"
        },
        {
          "name": "HTTP_PROXY",
          "value": "http://my.proxy.com"
        },
        {
          "name": "NO_PROXY",
          "value": "http://my.local.com"
        }
      ],
      "image": "image",
      "name": "init-container-with-env",
      "resources": {},
      "volumeMounts": [
        {
          "mountPath": "/etc/ssl/certs",
          "name": "ca-certs",
          "readOnly": true
        }
      ]
    }
  },
  {
    "op": "add",
    "path": "/spec/initContainers/0/env",
    "value": [
      {
        "name": "CA_CERTS_DATA_0",
        "value": "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n"
      }
    ]
  },
  {
    "op": "add",
    "path": "/spec/initContainers/0/volumeMounts",
    "value": [
      {
        "mountPath": "/workspace",
        "name": "ca-certs"
      }
    ]
  },
  {
    "op": "add",
    "path": "/spec/initContainers/0/imagePullPolicy",
    "value": "IfNotPresent"
  },
  {
    "op": "add",
    "path": "/spec/initContainers/0/securityContext",
    "value": {
	    "allowPrivilegeEscalation": false,
	    "capabilities": {"drop": ["ALL"]},
	    "privileged": false,
	    "runAsNonRoot": true,
	    "seccompProfile": {"type": "RuntimeDefault"}
    }
  },
  {
    "op": "replace",
    "path": "/spec/initContainers/0/name",
    "value": "setup-ca-certs"
  },
  {
    "op": "replace",
    "path": "/spec/initContainers/0/image",
    "value": "some-ca-certs-image"
  },
  {
    "op": "add",
    "path": "/spec/initContainers/0/workingDir",
    "value": "/workspace"
  },
  {
    "op": "replace",
    "path": "/spec/initContainers/1/name",
    "value": "init-container-without-env"
  },
  {
    "op": "add",
    "path": "/spec/initContainers/1/env/1",
    "value": {
      "name": "NO_PROXY",
      "value": "http://my.local.com"
    }
  },
  {
    "op": "replace",
    "path": "/spec/initContainers/1/env/0/name",
    "value": "HTTP_PROXY"
  },
  {
    "op": "replace",
    "path": "/spec/initContainers/1/env/0/value",
    "value": "http://my.proxy.com"
  },
  {
    "op": "add",
    "path": "/spec/initContainers/1/volumeMounts",
    "value": [
      {
        "mountPath": "/etc/ssl/certs",
        "name": "ca-certs",
        "readOnly": true
      }
    ]
  },
  {
    "op": "add",
    "path": "/spec/containers/0/env",
    "value": [
      {
        "name": "HTTP_PROXY",
        "value": "http://my.proxy.com"
      },
      {
        "name": "NO_PROXY",
        "value": "http://my.local.com"
      }
    ]
  },
  {
    "op": "add",
    "path": "/spec/containers/0/volumeMounts",
    "value": [
      {
        "mountPath": "/etc/ssl/certs",
        "name": "ca-certs",
        "readOnly": true
      }
    ]
  },
  {
    "op": "add",
    "path": "/spec/containers/1/env/1",
    "value": {
      "name": "NO_PROXY",
      "value": "http://my.local.com"
    }
  },
  {
    "op": "add",
    "path": "/spec/containers/1/env/1",
    "value": {
      "name": "HTTP_PROXY",
      "value": "http://my.proxy.com"
    }
  },
  {
    "op": "add",
    "path": "/spec/containers/1/volumeMounts",
    "value": [
      {
        "mountPath": "/etc/ssl/certs",
        "name": "ca-certs",
        "readOnly": true
      }
    ]
  }
]`
			var expectedPatch []jsonpatch.JsonPatchOperation
			err = json.Unmarshal([]byte(expectedJSON), &expectedPatch)
			require.NoError(t, err)

			assert.ElementsMatch(t, expectedPatch, actualPatch)
		})

		it("applies both env and certs changes for custom annotations", func() {
			testPod.Annotations = map[string]string{
				annotation: "some value",
			}

			bytes, err := json.Marshal(testPod)
			require.NoError(t, err)

			admissionRequest := &admissionv1.AdmissionRequest{
				Name: "testAdmissionRequest",
				Object: runtime.RawExtension{
					Raw: bytes,
				},
				Operation: admissionv1.Create,
				Resource:  metav1.GroupVersionResource{Version: "v1", Resource: "pods"},
			}

			ac, err := certinjectionwebhook.NewAdmissionController(
				name,
				path,
				func(ctx context.Context) context.Context { return ctx },
				[]string{},
				[]string{annotation},
				envVars,
				setupCACertsImage,
				caCertsData,
				corev1.LocalObjectReference{},
			)
			require.NoError(t, err)

			response := ac.Admit(ctx, admissionRequest)
			wtesting.ExpectAllowed(t, response)

			var actualPatch []jsonpatch.JsonPatchOperation
			err = json.Unmarshal(response.Patch, &actualPatch)
			require.NoError(t, err)

			expectedJSON := `[
  {
    "op": "add",
    "path": "/spec/volumes",
    "value": [
      {
        "emptyDir": {},
        "name": "ca-certs"
      }
    ]
  },
  {
    "op": "add",
    "path": "/spec/initContainers/2",
    "value": {
      "env": [
        {
          "name": "EXISTING",
          "value": "VALUE"
        },
        {
          "name": "HTTP_PROXY",
          "value": "http://my.proxy.com"
        },
        {
          "name": "NO_PROXY",
          "value": "http://my.local.com"
        }
      ],
      "image": "image",
      "name": "init-container-with-env",
      "resources": {},
      "volumeMounts": [
        {
          "mountPath": "/etc/ssl/certs",
          "name": "ca-certs",
          "readOnly": true
        }
      ]
    }
  },
  {
    "op": "add",
    "path": "/spec/initContainers/0/imagePullPolicy",
    "value": "IfNotPresent"
  },
  {
    "op": "add",
    "path": "/spec/initContainers/0/securityContext",
    "value": {
	    "allowPrivilegeEscalation": false,
	    "capabilities": {"drop": ["ALL"]},
	    "privileged": false,
	    "runAsNonRoot": true,
	    "seccompProfile": {"type": "RuntimeDefault"}
    }
  },
  {
    "op": "replace",
    "path": "/spec/initContainers/0/name",
    "value": "setup-ca-certs"
  },
  {
    "op": "replace",
    "path": "/spec/initContainers/0/image",
    "value": "some-ca-certs-image"
  },
  {
    "op": "add",
    "path": "/spec/initContainers/0/workingDir",
    "value": "/workspace"
  },
  {
    "op": "add",
    "path": "/spec/initContainers/0/env",
    "value": [
      {
        "name": "CA_CERTS_DATA_0",
        "value": "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n"
      }
    ]
  },
  {
    "op": "add",
    "path": "/spec/initContainers/0/volumeMounts",
    "value": [
      {
        "mountPath": "/workspace",
        "name": "ca-certs"
      }
    ]
  },
  {
    "op": "replace",
    "path": "/spec/initContainers/1/name",
    "value": "init-container-without-env"
  },
  {
    "op": "add",
    "path": "/spec/initContainers/1/env/1",
    "value": {
      "name": "NO_PROXY",
      "value": "http://my.local.com"
    }
  },
  {
    "op": "replace",
    "path": "/spec/initContainers/1/env/0/name",
    "value": "HTTP_PROXY"
  },
  {
    "op": "replace",
    "path": "/spec/initContainers/1/env/0/value",
    "value": "http://my.proxy.com"
  },
  {
    "op": "add",
    "path": "/spec/initContainers/1/volumeMounts",
    "value": [
      {
        "mountPath": "/etc/ssl/certs",
        "name": "ca-certs",
        "readOnly": true
      }
    ]
  },
  {
    "op": "add",
    "path": "/spec/containers/0/env",
    "value": [
      {
        "name": "HTTP_PROXY",
        "value": "http://my.proxy.com"
      },
      {
        "name": "NO_PROXY",
        "value": "http://my.local.com"
      }
    ]
  },
  {
    "op": "add",
    "path": "/spec/containers/0/volumeMounts",
    "value": [
      {
        "mountPath": "/etc/ssl/certs",
        "name": "ca-certs",
        "readOnly": true
      }
    ]
  },
  {
    "op": "add",
    "path": "/spec/containers/1/env/1",
    "value": {
      "name": "NO_PROXY",
      "value": "http://my.local.com"
    }
  },
  {
    "op": "add",
    "path": "/spec/containers/1/env/1",
    "value": {
      "name": "HTTP_PROXY",
      "value": "http://my.proxy.com"
    }
  },
  {
    "op": "add",
    "path": "/spec/containers/1/volumeMounts",
    "value": [
      {
        "mountPath": "/etc/ssl/certs",
        "name": "ca-certs",
        "readOnly": true
      }
    ]
  }
] `
			var expectedPatch []jsonpatch.JsonPatchOperation
			err = json.Unmarshal([]byte(expectedJSON), &expectedPatch)
			require.NoError(t, err)

			assert.ElementsMatch(t, expectedPatch, actualPatch)
		})

		it("only patches pods", func() {
			testPod.Annotations = map[string]string{
				annotation: "some value",
			}

			bytes, err := json.Marshal(testPod)
			require.NoError(t, err)

			admissionRequest := &admissionv1.AdmissionRequest{
				Name: "testAdmissionRequest",
				Object: runtime.RawExtension{
					Raw: bytes,
				},
				Operation: admissionv1.Create,
				Resource:  metav1.GroupVersionResource{Version: "v1", Resource: "containers"},
			}

			ac, err := certinjectionwebhook.NewAdmissionController(
				name,
				path,
				func(ctx context.Context) context.Context { return ctx },
				[]string{},
				[]string{annotation},
				envVars,
				setupCACertsImage,
				caCertsData,
				corev1.LocalObjectReference{},
			)
			require.NoError(t, err)

			response := ac.Admit(ctx, admissionRequest)
			wtesting.ExpectAllowed(t, response)
			require.Nil(t, response.Patch)
		})

		it("only processes pods marked with the configured label or configured service annotation by default", func() {
			testPod.Labels = nil
			testPod.Annotations = nil

			bytes, err := json.Marshal(testPod)
			require.NoError(t, err)

			admissionRequest := &admissionv1.AdmissionRequest{
				Name: "testAdmissionRequest",
				Object: runtime.RawExtension{
					Raw: bytes,
				},
				Operation: admissionv1.Create,
				Resource:  metav1.GroupVersionResource{Version: "v1", Resource: "pods"},
			}

			ac, err := certinjectionwebhook.NewAdmissionController(
				name,
				path,
				func(ctx context.Context) context.Context { return ctx },
				[]string{label},
				[]string{annotation},
				envVars,
				setupCACertsImage,
				caCertsData,
				corev1.LocalObjectReference{},
			)
			require.NoError(t, err)

			response := ac.Admit(ctx, admissionRequest)
			wtesting.ExpectAllowed(t, response)
			require.Nil(t, response.Patch)
		})

		it("sets the registry credentials on all containers on the pods that have the registry env vars", func() {
			testPod.Labels = map[string]string{
				label: "some value",
			}

			bytes, err := json.Marshal(testPod)
			require.NoError(t, err)

			admissionRequest := &admissionv1.AdmissionRequest{
				Name: "testAdmissionRequest",
				Object: runtime.RawExtension{
					Raw: bytes,
				},
				Operation: admissionv1.Create,
				Resource:  metav1.GroupVersionResource{Version: "v1", Resource: "pods"},
			}

			ac, err := certinjectionwebhook.NewAdmissionController(
				name,
				path,
				func(ctx context.Context) context.Context { return ctx },
				[]string{label},
				[]string{},
				[]corev1.EnvVar{},
				setupCACertsImage,
				caCertsData,
				corev1.LocalObjectReference{
					Name: "system-registry-credentials",
				},
			)
			require.NoError(t, err)

			response := ac.Admit(ctx, admissionRequest)
			wtesting.ExpectAllowed(t, response)

			var actualPatch []jsonpatch.JsonPatchOperation
			err = json.Unmarshal(response.Patch, &actualPatch)
			require.NoError(t, err)

			expectedJSON := "[{\"op\":\"add\",\"path\":\"/spec/volumes\",\"value\":[{\"emptyDir\":{},\"name\":\"ca-certs\"}]},{\"op\":\"add\",\"path\":\"/spec/imagePullSecrets\",\"value\":[{\"name\":\"system-registry-credentials\"}]},{\"op\":\"add\",\"path\":\"/spec/initContainers/2\",\"value\":{\"env\":[{\"name\":\"EXISTING\",\"value\":\"VALUE\"}],\"image\":\"image\",\"name\":\"init-container-with-env\",\"resources\":{},\"volumeMounts\":[{\"mountPath\":\"/etc/ssl/certs\",\"name\":\"ca-certs\",\"readOnly\":true}]}},{\"op\":\"add\",\"path\":\"/spec/initContainers/0/env\",\"value\":[{\"name\":\"CA_CERTS_DATA_0\",\"value\":\"-----BEGIN CERTIFICATE-----\\n-----END CERTIFICATE-----\\n\"}]},{\"op\":\"add\",\"path\":\"/spec/initContainers/0/volumeMounts\",\"value\":[{\"mountPath\":\"/workspace\",\"name\":\"ca-certs\"}]},{\"op\":\"add\",\"path\":\"/spec/initContainers/0/imagePullPolicy\",\"value\":\"IfNotPresent\"},{\"op\": \"add\", \"path\": \"/spec/initContainers/0/securityContext\", \"value\": {\"allowPrivilegeEscalation\": false, \"capabilities\": {\"drop\": [\"ALL\"]}, \"privileged\": false, \"runAsNonRoot\": true, \"seccompProfile\": {\"type\": \"RuntimeDefault\"}}},{\"op\":\"replace\",\"path\":\"/spec/initContainers/0/name\",\"value\":\"setup-ca-certs\"},{\"op\":\"replace\",\"path\":\"/spec/initContainers/0/image\",\"value\":\"some-ca-certs-image\"},{\"op\":\"add\",\"path\":\"/spec/initContainers/0/workingDir\",\"value\":\"/workspace\"},{\"op\":\"replace\",\"path\":\"/spec/initContainers/1/name\",\"value\":\"init-container-without-env\"},{\"op\":\"add\",\"path\":\"/spec/initContainers/1/volumeMounts\",\"value\":[{\"mountPath\":\"/etc/ssl/certs\",\"name\":\"ca-certs\",\"readOnly\":true}]},{\"op\":\"remove\",\"path\":\"/spec/initContainers/1/env\"},{\"op\":\"add\",\"path\":\"/spec/containers/0/volumeMounts\",\"value\":[{\"mountPath\":\"/etc/ssl/certs\",\"name\":\"ca-certs\",\"readOnly\":true}]},{\"op\":\"add\",\"path\":\"/spec/containers/1/volumeMounts\",\"value\":[{\"mountPath\":\"/etc/ssl/certs\",\"name\":\"ca-certs\",\"readOnly\":true}]}]"
			var expectedPatch []jsonpatch.JsonPatchOperation
			err = json.Unmarshal([]byte(expectedJSON), &expectedPatch)
			require.NoError(t, err)

			assert.ElementsMatch(t, expectedPatch, actualPatch)
		})

		it("sets the registry credentials on all containers on the pods that have the registry credentials env", func() {
			testPod.Annotations = map[string]string{
				annotation: "some value",
			}
			testPod.Spec.ImagePullSecrets = []corev1.LocalObjectReference{
				{Name: "app-registry-credentials"},
			}

			bytes, err := json.Marshal(testPod)
			require.NoError(t, err)

			admissionRequest := &admissionv1.AdmissionRequest{
				Name: "testAdmissionRequest",
				Object: runtime.RawExtension{
					Raw: bytes,
				},
				Operation: admissionv1.Create,
				Resource:  metav1.GroupVersionResource{Version: "v1", Resource: "pods"},
			}

			ac, err := certinjectionwebhook.NewAdmissionController(
				name,
				path,
				func(ctx context.Context) context.Context { return ctx },
				[]string{},
				[]string{annotation},
				[]corev1.EnvVar{},
				setupCACertsImage,
				caCertsData,
				corev1.LocalObjectReference{
					Name: "system-registry-credentials",
				},
			)
			require.NoError(t, err)

			response := ac.Admit(ctx, admissionRequest)
			wtesting.ExpectAllowed(t, response)

			var actualPatch []jsonpatch.JsonPatchOperation
			err = json.Unmarshal(response.Patch, &actualPatch)
			require.NoError(t, err)

			expectedJSON := "[{\"op\":\"add\",\"path\":\"/spec/volumes\",\"value\":[{\"emptyDir\":{},\"name\":\"ca-certs\"}]},{\"op\":\"add\",\"path\":\"/spec/imagePullSecrets/1\",\"value\":{\"name\":\"system-registry-credentials\"}},{\"op\":\"add\",\"path\":\"/spec/initContainers/2\",\"value\":{\"env\":[{\"name\":\"EXISTING\",\"value\":\"VALUE\"}],\"image\":\"image\",\"name\":\"init-container-with-env\",\"resources\":{},\"volumeMounts\":[{\"mountPath\":\"/etc/ssl/certs\",\"name\":\"ca-certs\",\"readOnly\":true}]}},{\"op\":\"add\",\"path\":\"/spec/initContainers/0/env\",\"value\":[{\"name\":\"CA_CERTS_DATA_0\",\"value\":\"-----BEGIN CERTIFICATE-----\\n-----END CERTIFICATE-----\\n\"}]},{\"op\":\"add\",\"path\":\"/spec/initContainers/0/volumeMounts\",\"value\":[{\"mountPath\":\"/workspace\",\"name\":\"ca-certs\"}]},{\"op\":\"add\",\"path\":\"/spec/initContainers/0/imagePullPolicy\",\"value\":\"IfNotPresent\"},{\"op\": \"add\", \"path\": \"/spec/initContainers/0/securityContext\", \"value\": {\"allowPrivilegeEscalation\": false, \"capabilities\": {\"drop\": [\"ALL\"]}, \"privileged\": false, \"runAsNonRoot\": true, \"seccompProfile\": {\"type\": \"RuntimeDefault\"}}},{\"op\":\"replace\",\"path\":\"/spec/initContainers/0/name\",\"value\":\"setup-ca-certs\"},{\"op\":\"replace\",\"path\":\"/spec/initContainers/0/image\",\"value\":\"some-ca-certs-image\"},{\"op\":\"add\",\"path\":\"/spec/initContainers/0/workingDir\",\"value\":\"/workspace\"},{\"op\":\"replace\",\"path\":\"/spec/initContainers/1/name\",\"value\":\"init-container-without-env\"},{\"op\":\"add\",\"path\":\"/spec/initContainers/1/volumeMounts\",\"value\":[{\"mountPath\":\"/etc/ssl/certs\",\"name\":\"ca-certs\",\"readOnly\":true}]},{\"op\":\"remove\",\"path\":\"/spec/initContainers/1/env\"},{\"op\":\"add\",\"path\":\"/spec/containers/0/volumeMounts\",\"value\":[{\"mountPath\":\"/etc/ssl/certs\",\"name\":\"ca-certs\",\"readOnly\":true}]},{\"op\":\"add\",\"path\":\"/spec/containers/1/volumeMounts\",\"value\":[{\"mountPath\":\"/etc/ssl/certs\",\"name\":\"ca-certs\",\"readOnly\":true}]}]"
			var expectedPatch []jsonpatch.JsonPatchOperation
			err = json.Unmarshal([]byte(expectedJSON), &expectedPatch)
			require.NoError(t, err)

			assert.ElementsMatch(t, expectedPatch, actualPatch)
		})

	})

	it("#Path returns path", func() {
		ac, err := certinjectionwebhook.NewAdmissionController(name, path, nil, []string{"label"}, nil, nil, "", "", corev1.LocalObjectReference{})
		require.NoError(t, err)

		require.Equal(t, ac.Path(), path)
	})

}

func TestParseResource(t *testing.T) {
	tests := []struct {
		name      string
		envVar    string
		envValue  string
		expectErr bool
		expectVal string
	}{
		{"Valid CPU Request", "TEST_CPU_REQUEST", "100m", false, "100m"},
		{"Valid Memory Request", "TEST_MEMORY_REQUEST", "128Mi", false, "128Mi"},
		{"Invalid Format", "TEST_INVALID", "invalid", true, ""},
		{"Missing Env Var", "TEST_MISSING", "", false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set or unset the environment variable
			if tt.envValue != "" {
				os.Setenv(tt.envVar, tt.envValue)
				defer os.Unsetenv(tt.envVar)
			} else {
				os.Unsetenv(tt.envVar)
			}

			qty, err := certinjectionwebhook.ParseResource(tt.envVar)
			if (err != nil) != tt.expectErr {
				t.Errorf("Expected error: %v, got: %v", tt.expectErr, err)
			}

			if err == nil && tt.expectVal != "" && qty.String() != tt.expectVal {
				t.Errorf("Expected value: %s, got: %s", tt.expectVal, qty.String())
			}
		})
	}
}

func TestResourceRequirementsParsing(t *testing.T) {
	// Set environment variables
	os.Setenv("INIT_CONTAINER_CPU_REQUEST", "200m")
	os.Setenv("INIT_CONTAINER_MEMORY_REQUEST", "256Mi")
	os.Setenv("INIT_CONTAINER_CPU_LIMIT", "1")
	os.Setenv("INIT_CONTAINER_MEMORY_LIMIT", "512Mi")
	defer func() {
		os.Unsetenv("INIT_CONTAINER_CPU_REQUEST")
		os.Unsetenv("INIT_CONTAINER_MEMORY_REQUEST")
		os.Unsetenv("INIT_CONTAINER_CPU_LIMIT")
		os.Unsetenv("INIT_CONTAINER_MEMORY_LIMIT")
	}()

	var resources corev1.ResourceRequirements

	// Apply the logic under test
	if cpuRequest, err := certinjectionwebhook.ParseResource("INIT_CONTAINER_CPU_REQUEST"); err == nil {
		if resources.Requests == nil {
			resources.Requests = corev1.ResourceList{}
		}
		resources.Requests[corev1.ResourceCPU] = cpuRequest
	}
	if memoryRequest, err := certinjectionwebhook.ParseResource("INIT_CONTAINER_MEMORY_REQUEST"); err == nil {
		if resources.Requests == nil {
			resources.Requests = corev1.ResourceList{}
		}
		resources.Requests[corev1.ResourceMemory] = memoryRequest
	}
	if cpuLimit, err := certinjectionwebhook.ParseResource("INIT_CONTAINER_CPU_LIMIT"); err == nil {
		if resources.Limits == nil {
			resources.Limits = corev1.ResourceList{}
		}
		resources.Limits[corev1.ResourceCPU] = cpuLimit
	}
	if memoryLimit, err := certinjectionwebhook.ParseResource("INIT_CONTAINER_MEMORY_LIMIT"); err == nil {
		if resources.Limits == nil {
			resources.Limits = corev1.ResourceList{}
		}
		resources.Limits[corev1.ResourceMemory] = memoryLimit
	}

	expectedRequests := map[corev1.ResourceName]string{
		corev1.ResourceCPU:    "200m",
		corev1.ResourceMemory: "256Mi",
	}
	expectedLimits := map[corev1.ResourceName]string{
		corev1.ResourceCPU:    "1",
		corev1.ResourceMemory: "512Mi",
	}

	for k, v := range expectedRequests {
		qty := resources.Requests[k] // Copy value from map
		if qty.String() != v {
			t.Errorf("Expected request %s for %s, got %s", v, k, qty.String())
		}
	}

	for k, v := range expectedLimits {
		qty := resources.Limits[k] // Copy value from map
		if qty.String() != v {
			t.Errorf("Expected limit %s for %s, got %s", v, k, qty.String())
		}
	}
}
