//go:build integration
// +build integration

package gcpsecretsmanager_test

import (
	"math/rand"
	"os"
	"testing"
	"time"

	"github.com/jenkins-x-plugins/secretfacade/pkg/iam/gcpiam"
	"github.com/jenkins-x-plugins/secretfacade/pkg/secretstore"
	"github.com/jenkins-x-plugins/secretfacade/pkg/secretstore/gcpsecretsmanager"
	"github.com/stretchr/testify/assert"
)

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
var projectId string

func init() {
	rand.Seed(time.Now().UTC().UnixNano())
	osProjectId := os.Getenv("GCP_PROJECT_ID")
	if osProjectId == "" {
		projectId = "475686452636"
	}
}

func RandStringRunes(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

func TestGcpSecretManagerBasicSet(t *testing.T) {
	creds, err := gcpiam.DefaultCredentials()
	secretName := RandStringRunes(12)
	secretValue := "secretvalue"
	assert.NoError(t, err)
	mgr := gcpsecretsmanager.NewGcpSecretsManager(*creds)
	err = mgr.SetSecret(projectId, secretName, &secretstore.SecretValue{
		Value: secretValue,
	})
	assert.NoError(t, err)

	val, err := mgr.GetSecret(projectId, secretName, "")
	assert.NoError(t, err)
	assert.Equal(t, secretValue, val)
}

func TestGcpSecretManagerPropertySet(t *testing.T) {
	creds, err := gcpiam.DefaultCredentials()
	secretName := RandStringRunes(12)
	secretValue := "{\"prop1\":\"val1\",\"prop2\":\"val2\"}"
	assert.NoError(t, err)
	mgr := gcpsecretsmanager.NewGcpSecretsManager(*creds)
	err = mgr.SetSecret(projectId, secretName, &secretstore.SecretValue{
		PropertyValues: map[string]string{
			"prop1": "val1",
			"prop2": "val2",
		},
	})
	assert.NoError(t, err)

	val, err := mgr.GetSecret(projectId, secretName, "")
	assert.NoError(t, err)
	assert.Equal(t, secretValue, val)

	prop1, err := mgr.GetSecret(projectId, secretName, "prop1")
	assert.NoError(t, err)
	assert.Equal(t, "val1", prop1)

	// Now try set only one property on existing secret to check preservation
	err = mgr.SetSecret(projectId, secretName, &secretstore.SecretValue{
		PropertyValues: map[string]string{
			"prop1": "vala",
		},
	})
	assert.NoError(t, err)

	propa, err := mgr.GetSecret(projectId, secretName, "prop1")
	assert.NoError(t, err)
	assert.Equal(t, "vala", propa)

	prop2, err := mgr.GetSecret(projectId, secretName, "prop2")
	assert.NoError(t, err)
	assert.Equal(t, "val2", prop2)
}
