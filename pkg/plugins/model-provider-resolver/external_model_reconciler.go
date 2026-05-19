/*
Copyright 2026 The opendatahub.io Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package model_provider_resolver

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	logutil "sigs.k8s.io/gateway-api-inference-extension/pkg/common/observability/logging"

	inferencev1alpha1 "github.com/opendatahub-io/ai-gateway-payload-processing/api/inference/v1alpha1"
)

// externalModelGVK is the GroupVersionKind for ExternalModel CRD.
var externalModelGVK = schema.GroupVersionKind{
	Group:   inferencev1alpha1.GroupVersion.Group,
	Version: inferencev1alpha1.GroupVersion.Version,
	Kind:    "ExternalModel",
}

// externalModelReconciler watches ExternalModel CRDs and updates the model store
// with provider, credential, and config information from the referenced ExternalProvider.
type externalModelReconciler struct {
	client.Reader
	store *modelInfoStore
}

// Reconcile handles create/update/delete events for ExternalModel resources.
// It resolves the referenced ExternalProvider to extract config and credentials.
func (r *externalModelReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx).V(logutil.DEFAULT)
	logger.Info("reconciling ExternalModel", "name", req.Name, "namespace", req.Namespace)

	externalModel := &inferencev1alpha1.ExternalModel{}
	if err := r.Get(ctx, req.NamespacedName, externalModel); err != nil {
		if errors.IsNotFound(err) {
			r.store.deleteExternalModel(req.NamespacedName)
			logger.Info("ExternalModel removed from store", "name", req.Name, "namespace", req.Namespace)
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("unable to get ExternalModel: %w", err)
	}

	if !externalModel.GetDeletionTimestamp().IsZero() {
		r.store.deleteExternalModel(req.NamespacedName)
		logger.Info("ExternalModel removed from store (deletion)", "name", req.Name, "namespace", req.Namespace)
		return ctrl.Result{}, nil
	}

	if len(externalModel.Spec.ExternalProviderRefs) == 0 {
		logger.Info("ExternalModel has no provider refs, skipping", "name", req.Name)
		return ctrl.Result{}, nil
	}

	providerRef := externalModel.Spec.ExternalProviderRefs[0]

	externalProvider := &inferencev1alpha1.ExternalProvider{}
	providerKey := types.NamespacedName{
		Name:      providerRef.Ref.Name,
		Namespace: req.Namespace,
	}
	if err := r.Get(ctx, providerKey, externalProvider); err != nil {
		if errors.IsNotFound(err) {
			logger.Info("referenced ExternalProvider not found", "provider", providerKey.String())
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("unable to get ExternalProvider: %w", err)
	}

	info := &externalModelInfo{
		provider:        externalProvider.Spec.Provider,
		targetModel:     providerRef.TargetModel,
<<<<<<< Updated upstream
		endpoint:        externalProvider.Spec.Endpoint,
=======
>>>>>>> Stashed changes
		secretName:      externalProvider.Spec.Auth.SecretRef.Name,
		secretNamespace: req.Namespace,
		providerConfig:  externalProvider.Spec.Config,
	}
	r.store.addOrUpdateExternalModel(req.NamespacedName, info)

<<<<<<< Updated upstream
	logger.Info("updated model store", "provider", info.provider, "targetModel", info.targetModel, "endpoint", info.endpoint, "hasConfig", info.providerConfig != nil)
=======
	logger.Info("updated model store", "provider", info.provider, "targetModel", info.targetModel, "hasConfig", info.providerConfig != nil)
>>>>>>> Stashed changes
	return ctrl.Result{}, nil
}
