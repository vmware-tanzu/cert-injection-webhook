// Copyright 2020-Present VMware, Inc.
// SPDX-License-Identifier: Apache-2.0

package certinjectionwebhook

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"knative.dev/pkg/apis"
	"knative.dev/pkg/apis/duck"
	"knative.dev/pkg/logging"
	"knative.dev/pkg/webhook"
	"os"

	"github.com/vmware-tanzu/cert-injection-webhook/pkg/certs"
)

const (
	caCertsVolumeName = "ca-certs"
	caCertsMountPath  = "/etc/ssl/certs"
)

var (
	errMissingNewObject = errors.New("the new object may not be nil")
	podResource         = metav1.GroupVersionResource{Version: "v1", Resource: "pods"}
)

// Implements webhook.AdmissionController
type admissionController struct {
	name string
	path string

	withContext func(context.Context) context.Context

	labels            []string
	annotations       []string
	envVars           []corev1.EnvVar
	setupCACertsImage string
	caCertsData       string
	imagePullSecrets  corev1.LocalObjectReference
}

func NewAdmissionController(
	name string,
	path string,
	wc func(context.Context) context.Context,

	labels []string,
	annotations []string,
	envVars []corev1.EnvVar,
	setupCACertsImage string,
	caCertsData string,
	imagePullSecrets corev1.LocalObjectReference,
) (*admissionController, error) {

	if len(labels) == 0 && len(annotations) == 0 {
		return nil, errors.New("at least one label or annotation required")
	}

	return &admissionController{
		name:              name,
		path:              path,
		withContext:       wc,
		labels:            labels,
		annotations:       annotations,
		envVars:           envVars,
		setupCACertsImage: setupCACertsImage,
		caCertsData:       caCertsData,
		imagePullSecrets:  imagePullSecrets,
	}, nil
}

func (ac *admissionController) Path() string {
	return ac.path
}

func (ac *admissionController) Admit(ctx context.Context, request *admissionv1.AdmissionRequest) *admissionv1.AdmissionResponse {
	if ac.withContext != nil {
		ctx = ac.withContext(ctx)
	}

	logger := logging.FromContext(ctx)

	if request.Resource != podResource {
		logger.Infof("expected resource to be %v", podResource)
		return &admissionv1.AdmissionResponse{Allowed: true}
	}

	switch request.Operation {
	case admissionv1.Create:
	default:
		logger.Infof("Unhandled webhook operation, letting it through %v", request.Operation)
		return &admissionv1.AdmissionResponse{Allowed: true}
	}

	raw := request.Object.Raw
	pod := corev1.Pod{}
	if _, _, err := universalDeserializer.Decode(raw, nil, &pod); err != nil {
		reason := fmt.Sprintf("could not deserialize pod object: %v", err)
		logger.Error(reason)
		result := apierrors.NewBadRequest(reason).Status()
		return &admissionv1.AdmissionResponse{
			Result:  &result,
			Allowed: true,
		}
	}

	if pod.Spec.NodeSelector["kubernetes.io/os"] == "windows" {
		return &admissionv1.AdmissionResponse{Allowed: true}
	}

	if !(intersect(ac.labels, pod.Labels) || intersect(ac.annotations, pod.Annotations)) {
		logger.Info("does not contain matching labels or annotations, letting it through")
		return &admissionv1.AdmissionResponse{Allowed: true}
	}

	patchBytes, err := ac.mutate(ctx, request)
	if err != nil {
		logger.Error(fmt.Sprintf("mutation failed: %v", err))
		status := webhook.MakeErrorStatus("mutation failed: %v", err)
		return status
	}
	logger.Infof("Kind: %q PatchBytes: %v", request.Kind, string(patchBytes))

	return &admissionv1.AdmissionResponse{
		Patch:   patchBytes,
		Allowed: true,
		PatchType: func() *admissionv1.PatchType {
			pt := admissionv1.PatchTypeJSONPatch
			return &pt
		}(),
	}
}

func (ac *admissionController) mutate(ctx context.Context, req *admissionv1.AdmissionRequest) ([]byte, error) {
	newBytes := req.Object.Raw

	var newObj corev1.Pod
	if len(newBytes) != 0 {
		newDecoder := json.NewDecoder(bytes.NewBuffer(newBytes))
		if err := newDecoder.Decode(&newObj); err != nil {
			return nil, fmt.Errorf("cannot decode incoming new object: %v", err)
		}
	}

	var patches duck.JSONPatch
	var err error

	ctx = apis.WithinCreate(ctx)
	ctx = apis.WithUserInfo(ctx, &req.UserInfo)

	if patches, err = ac.setBuildServicePodDefaults(ctx, patches, newObj); err != nil {
		return nil, errors.Wrap(err, "Failed to set default env vars and ca cert on pod")
	}

	if &newObj == nil {
		return nil, errMissingNewObject
	}
	return json.Marshal(patches)
}

func (ac *admissionController) SetEnvVars(ctx context.Context, obj *corev1.Pod) {
	if len(ac.envVars) == 0 {
		return
	}

	for i := range obj.Spec.Containers {
		for _, envVar := range ac.envVars {
			obj.Spec.Containers[i].Env = append(obj.Spec.Containers[i].Env, envVar)
		}
	}

	for i := range obj.Spec.InitContainers {
		for _, envVar := range ac.envVars {
			obj.Spec.InitContainers[i].Env = append(obj.Spec.InitContainers[i].Env, envVar)
		}
	}
}

func ParseResource(envVar string) (resource.Quantity, error) {
	value, found := os.LookupEnv(envVar)
	if !found {
		return resource.Quantity{}, nil // Return an empty Quantity if env var is missing
	}
	qty, err := resource.ParseQuantity(value)
	if err != nil {
		return resource.Quantity{}, fmt.Errorf("failed to parse %s: %w", envVar, err)
	}
	return qty, nil
}

func (ac *admissionController) SetCaCerts(ctx context.Context, obj *corev1.Pod) {
	if ac.caCertsData == "" {
		return
	}

	volume := corev1.Volume{
		Name: caCertsVolumeName,
		VolumeSource: corev1.VolumeSource{
			EmptyDir: &corev1.EmptyDirVolumeSource{},
		},
	}
	obj.Spec.Volumes = append(obj.Spec.Volumes, volume)

	mount := corev1.VolumeMount{
		Name:      caCertsVolumeName,
		MountPath: caCertsMountPath,
		ReadOnly:  true,
	}
	for i := range obj.Spec.InitContainers {
		obj.Spec.InitContainers[i].VolumeMounts = append(obj.Spec.InitContainers[i].VolumeMounts, mount)
	}
	for i := range obj.Spec.Containers {
		obj.Spec.Containers[i].VolumeMounts = append(obj.Spec.Containers[i].VolumeMounts, mount)
	}

	if ac.imagePullSecrets != (corev1.LocalObjectReference{}) {
		obj.Spec.ImagePullSecrets = append(obj.Spec.ImagePullSecrets, ac.imagePullSecrets)
	}

	var envVars []corev1.EnvVar
	for i, cert := range certs.Split(ac.caCertsData) {
		envVars = append(envVars, corev1.EnvVar{
			Name:  fmt.Sprintf("CA_CERTS_DATA_%d", i),
			Value: cert,
		})
	}

	var resources corev1.ResourceRequirements

	if cpuRequest, err := ParseResource("INIT_CONTAINER_CPU_REQUEST"); err == nil {
		if resources.Requests == nil {
			resources.Requests = corev1.ResourceList{}
		}
		resources.Requests[corev1.ResourceCPU] = cpuRequest
	} else {
		fmt.Printf("Warning: %v\n", err)
	}

	if memoryRequest, err := ParseResource("INIT_CONTAINER_MEMORY_REQUEST"); err == nil {
		if resources.Requests == nil {
			resources.Requests = corev1.ResourceList{}
		}
		resources.Requests[corev1.ResourceMemory] = memoryRequest
	} else {
		fmt.Printf("Warning: %v\n", err)
	}

	if cpuLimit, err := ParseResource("INIT_CONTAINER_CPU_LIMIT"); err == nil {
		if resources.Limits == nil {
			resources.Limits = corev1.ResourceList{}
		}
		resources.Limits[corev1.ResourceCPU] = cpuLimit
	} else {
		fmt.Printf("Warning: %v\n", err)
	}

	if memoryLimit, err := ParseResource("INIT_CONTAINER_MEMORY_LIMIT"); err == nil {
		if resources.Limits == nil {
			resources.Limits = corev1.ResourceList{}
		}
		resources.Limits[corev1.ResourceMemory] = memoryLimit
	} else {
		fmt.Printf("Warning: %v\n", err)
	}

	container := corev1.Container{
		Name:            "setup-ca-certs",
		Image:           ac.setupCACertsImage,
		Env:             envVars,
		ImagePullPolicy: corev1.PullIfNotPresent,
		WorkingDir:      "/workspace",
		VolumeMounts: []corev1.VolumeMount{
			{
				Name:      caCertsVolumeName,
				MountPath: "/workspace",
			},
		},
		SecurityContext: &corev1.SecurityContext{
			RunAsNonRoot:             boolPointer(true),
			AllowPrivilegeEscalation: boolPointer(false),
			Privileged:               boolPointer(false),
			SeccompProfile:           &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
			Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
		},
	}

	if len(resources.Requests) > 0 || len(resources.Limits) > 0 {
		container.Resources = resources
	}

	obj.Spec.InitContainers = append([]corev1.Container{container}, obj.Spec.InitContainers...)
}

func (ac *admissionController) setBuildServicePodDefaults(ctx context.Context, patches duck.JSONPatch, pod corev1.Pod) (duck.JSONPatch, error) {
	before, after := pod.DeepCopyObject(), pod
	ac.SetEnvVars(ctx, &after)
	ac.SetCaCerts(ctx, &after)

	patch, err := duck.CreatePatch(before, after)
	if err != nil {
		return nil, err
	}

	return append(patches, patch...), nil
}

var universalDeserializer = serializer.NewCodecFactory(runtime.NewScheme()).UniversalDeserializer()

func intersect(a []string, b map[string]string) bool {
	for _, k := range a {
		if _, ok := b[k]; ok {
			return true
		}
	}
	return false
}

func boolPointer(b bool) *bool {
	return &b
}
