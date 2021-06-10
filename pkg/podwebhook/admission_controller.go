// Copyright 2020-Present VMware, Inc.
// SPDX-License-Identifier: Apache-2.0

package podwebhook

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/pkg/errors"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"knative.dev/pkg/apis"
	"knative.dev/pkg/apis/duck"
	"knative.dev/pkg/logging"
	"knative.dev/pkg/webhook"
)

const (
	caCertsVolumeName = "ca-certs"
	caCertsMountPath  = "/etc/ssl/certs"
)

var (
	errMissingNewObject       = errors.New("the new object may not be nil")
	podResource               = metav1.GroupVersionResource{Version: "v1", Resource: "pods"}
	root                int64 = 0
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
	case admissionv1.Create, admissionv1.Update:
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
	
	if pod.Spec.NodeSelector["kubernetes.io/os"] == "windows"{
		return &admissionv1.AdmissionResponse{Allowed: true}
	}

	if !(intersect(ac.labels, pod.Labels) || intersect(ac.annotations, pod.Annotations)) {
		logger.Info("does not contain matching labels or annotations, letting it through")
		return &admissionv1.AdmissionResponse{Allowed: true}
	}

	patchBytes, err := ac.mutate(ctx, request)
	if err != nil {
		reason := fmt.Sprintf("mutation failed: %v", err)
		logger.Error(reason)
		status := webhook.MakeErrorStatus(reason)
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
	oldBytes := req.OldObject.Raw

	var oldObj, newObj corev1.Pod

	if len(newBytes) != 0 {
		newDecoder := json.NewDecoder(bytes.NewBuffer(newBytes))
		if err := newDecoder.Decode(&newObj); err != nil {
			return nil, fmt.Errorf("cannot decode incoming new object: %v", err)
		}
	}
	if len(oldBytes) != 0 {
		oldDecoder := json.NewDecoder(bytes.NewBuffer(oldBytes))
		if err := oldDecoder.Decode(&oldObj); err != nil {
			return nil, fmt.Errorf("cannot decode incoming old object: %v", err)
		}
	}
	var patches duck.JSONPatch

	var err error

	if &oldObj != nil {
		if req.SubResource == "" {
			ctx = apis.WithinUpdate(ctx, oldObj)
		} else {
			ctx = apis.WithinSubResourceUpdate(ctx, oldObj, req.SubResource)
		}
	} else {
		ctx = apis.WithinCreate(ctx)
	}
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

	container := corev1.Container{
		Name:  "setup-ca-certs",
		Image: ac.setupCACertsImage,
		Env: []corev1.EnvVar{
			{
				Name:  "CA_CERTS_DATA",
				Value: ac.caCertsData,
			},
		},
		ImagePullPolicy: corev1.PullIfNotPresent,
		WorkingDir:      "/workspace",
		VolumeMounts: []corev1.VolumeMount{
			{
				Name:      caCertsVolumeName,
				MountPath: "/workspace",
			},
		},
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
		if v, ok := b[k]; ok && v != "" {
			return true
		}
	}
	return false
}
