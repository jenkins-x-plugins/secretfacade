package secretstore

import (
	"encoding/json"

	corev1 "k8s.io/api/core/v1"

	"dario.cat/mergo"
)

type SecretValue struct {
	Value          string
	PropertyValues map[string]string
	Annotations    map[string]string
	Labels         map[string]string

	// SecretType is only really needed when using local secrets so that we
	// can populate the Secret resource with the correct type
	SecretType corev1.SecretType
	Overwrite  bool
}

func (sv *SecretValue) ToString() string {
	if sv.Value != "" {
		return sv.Value
	}
	j, err := json.Marshal(sv.PropertyValues)
	if err != nil {
		return "{}"
	}
	return string(j)
}

func (sv *SecretValue) MergeExistingSecret(existing map[string]string) string {
	if existing == nil {
		return sv.ToString()
	}
	if sv.Value != "" {
		return sv.Value
	}
	err := mergo.Merge(&existing, sv.PropertyValues, mergo.WithOverride)
	if err != nil {
		return "{}"
	}

	j, err := json.Marshal(existing)
	if err != nil {
		return "{}"
	}
	return string(j)
}
