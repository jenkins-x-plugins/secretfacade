package azuresecrets_test

import (
	"os"
	"testing"

	"github.com/jenkins-x-plugins/secretfacade/pkg/secretstore"
	"github.com/jenkins-x-plugins/secretfacade/pkg/secretstore/azuresecrets"
	"github.com/stretchr/testify/assert"
)

func TestAzureKey(t *testing.T) {

	keyVaultName := os.Getenv("AZURE_KEY_VAULT")
	if keyVaultName == "" {
		t.SkipNow()
		return
	}
	secretMgr := azuresecrets.NewAzureKeyVaultSecretManager()

	err := secretMgr.SetSecret(keyVaultName, "testsecret", &secretstore.SecretValue{
		PropertyValues: map[string]string{
			"username": "thisisausername",
			"password": "thisisapassword",
		},
	})
	assert.NoError(t, err)

	username, err := secretMgr.GetSecret(keyVaultName, "testsecret", "username")
	assert.NoError(t, err)
	assert.Equal(t, "thisisausername", username)

}
