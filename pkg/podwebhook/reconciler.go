// Copyright 2020-Present VMware, Inc.
// SPDX-License-Identifier: Apache-2.0

package podwebhook

import (
	"context"
	"fmt"

	"k8s.io/client-go/kubernetes"
	admissionlisters "k8s.io/client-go/listers/admissionregistration/v1"
	corelisters "k8s.io/client-go/listers/core/v1"
	"knative.dev/pkg/kmp"
	"knative.dev/pkg/logging"
	"knative.dev/pkg/ptr"
	"knative.dev/pkg/system"
	certresources "knative.dev/pkg/webhook/certificates/resources"
)

// Implements controller.Reconciler
type reconciler struct {
	name string
	path string

	k8sClient    kubernetes.Interface
	mwhlister    admissionlisters.MutatingWebhookConfigurationLister
	secretlister corelisters.SecretLister

	secretName string
}

func NewReconciler(name string,
	path string,
	k8sClient kubernetes.Interface,
	mwhlister admissionlisters.MutatingWebhookConfigurationLister,
	secretlister corelisters.SecretLister,
	secretName string) *reconciler {
	return &reconciler{
		name:         name,
		path:         path,
		k8sClient:    k8sClient,
		mwhlister:    mwhlister,
		secretlister: secretlister,
		secretName:   secretName,
	}
}

func (r *reconciler) Reconcile(ctx context.Context, key string) error {
	logger := logging.FromContext(ctx)

	secret, err := r.secretlister.Secrets(system.Namespace()).Get(r.secretName)
	if err != nil {
		logger.Errorf("Error fetching secret: %v", err)
		return err
	}
	caCert, ok := secret.Data[certresources.CACert]
	if !ok {
		return fmt.Errorf("secret %q is missing %q key", r.secretName, certresources.CACert)
	}

	return r.reconcileMutatingWebhook(ctx, caCert)
}

func (r *reconciler) reconcileMutatingWebhook(ctx context.Context, caCert []byte) error {
	logger := logging.FromContext(ctx)

	configuredWebhook, err := r.mwhlister.Get(r.name)
	if err != nil {
		return fmt.Errorf("error retrieving webhook: %v", err)
	}

	webhook := configuredWebhook.DeepCopy()

	for i, wh := range webhook.Webhooks {
		if wh.Name != webhook.Name {
			continue
		}
		webhook.Webhooks[i].ClientConfig.CABundle = caCert
		if webhook.Webhooks[i].ClientConfig.Service == nil {
			return fmt.Errorf("missing service reference for webhook: %s", wh.Name)
		}
		webhook.Webhooks[i].ClientConfig.Service.Path = ptr.String(r.path)
	}

	if ok, err := kmp.SafeEqual(configuredWebhook, webhook); err != nil {
		return fmt.Errorf("error diffing webhooks: %v", err)
	} else if !ok {
		logger.Info("Updating webhook")
		mwhclient := r.k8sClient.AdmissionregistrationV1().MutatingWebhookConfigurations()
		if _, err := mwhclient.Update(webhook); err != nil {
			return fmt.Errorf("failed to update webhook: %v", err)
		}
	} else {
		logger.Info("Webhook is valid")
	}
	return nil
}
