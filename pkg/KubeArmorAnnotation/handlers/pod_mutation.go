package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

type PodAnnotator struct {
	Client  client.Client
	decoder *admission.Decoder
	Logger  logr.Logger
}

const k8sVisibility = "none"

// +kubebuilder:webhook:path=/mutate-pods,mutating=true,failurePolicy=Fail,groups="",resources=pods,verbs=create;update,versions=v1,name=annotation.kubearmor.com,admissionReviewVersions=v1,sideEffects=NoneOnDryRun

func (a *PodAnnotator) Handle(ctx context.Context, req admission.Request) admission.Response {
	pod := &corev1.Pod{}
	log := a.Logger
	log.Info("Heree 1")
	err := a.decoder.Decode(req, pod)
	if err != nil {
		return admission.Errored(http.StatusBadRequest, err)
	}

	if pod.Annotations == nil {
		pod.Annotations = map[string]string{}
	}

	// == Policy == //

	if _, ok := pod.Annotations["kubearmor-policy"]; !ok {
		// if no annotation is set enable kubearmor by default
		pod.Annotations["kubearmor-policy"] = "enabled"
	} else if pod.Annotations["kubearmor-policy"] != "enabled" && pod.Annotations["kubearmor-policy"] != "disabled" && pod.Annotations["kubearmor-policy"] != "audited" {
		// if kubearmor policy is not set correctly, default it to enabled
		pod.Annotations["kubearmor-policy"] = "enabled"
	}

	// == Exception == //

	// exception: kubernetes app
	if pod.Namespace == "kube-system" {

		if _, ok := pod.Labels["k8s-app"]; ok {
			pod.Annotations["kubearmor-policy"] = "audited"
		}

		if value, ok := pod.Labels["component"]; ok {
			if value == "etcd" || value == "kube-apiserver" || value == "kube-controller-manager" || value == "kube-scheduler" {
				pod.Annotations["kubearmor-policy"] = "audited"
			}
		}
	}

	// exception: cilium-operator
	if _, ok := pod.Labels["io.cilium/app"]; ok {
		pod.Annotations["kubearmor-policy"] = "audited"
	}

	// exception: kubearmor
	if _, ok := pod.Labels["kubearmor-app"]; ok {
		pod.Annotations["kubearmor-policy"] = "audited"
	}

	// == Visibility == //

	if _, ok := pod.Annotations["kubearmor-visibility"]; !ok {
		pod.Annotations["kubearmor-visibility"] = k8sVisibility
	}

	// == Add kubearmor annotations == //

	// Get existant kubearmor annotations
	appArmorAnnotations := map[string]string{}
	for k, v := range pod.Annotations {
		if strings.HasPrefix(k, "container.apparmor.security.beta.kubernetes.io/") {
			if v == "unconfined" {
				containerName := strings.Split(k, "/")[1]
				appArmorAnnotations[containerName] = v
			} else {
				containerName := strings.Split(k, "/")[1]
				appArmorAnnotations[containerName] = strings.Split(v, "/")[1]
			}
		}
	}

	// Get the remaining containers / not addressed explecitly in the annotation
	for _, container := range pod.Spec.Containers {
		if _, ok := appArmorAnnotations[container.Name]; !ok {
			appArmorAnnotations[container.Name] = "kubearmor-" + pod.Namespace + "-" + container.Name
		}
	}

	// Add kubearmor annotations to the pod

	for k, v := range appArmorAnnotations {
		if v == "unconfined" {
			continue
		}
		pod.Annotations["container.apparmor.security.beta.kubernetes.io/"+k] = "localhost/" + v
	}

	// send the mutation response
	marshaledPod, err := json.Marshal(pod)
	if err != nil {
		return admission.Errored(http.StatusInternalServerError, err)
	}
	return admission.PatchResponseFromRaw(req.Object.Raw, marshaledPod)
}
