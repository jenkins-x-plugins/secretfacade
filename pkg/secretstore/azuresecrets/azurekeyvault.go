package azuresecrets

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/jenkins-x-plugins/secretfacade/pkg/iam/azureiam"
	"github.com/jenkins-x-plugins/secretfacade/pkg/secretstore"
	"net/url"
)

func NewAzureKeyVaultSecretManager() secretstore.Interface {
	return &azureKeyVaultSecretManager{}
}

type azureKeyVaultSecretManager struct {
}

func (a *azureKeyVaultSecretManager) GetSecret(vaultName, secretName, secretKey string) (string, error) {
	keyClient, err := getSecretOpsClient(vaultName)
	if err != nil {
		return "", fmt.Errorf("unable to create key ops client: %w", err)
	}
	bundle, err := keyClient.GetSecret(context.TODO(), secretName, "", nil)
	if err != nil {
		return "", fmt.Errorf("unable to retrieve secret %s from vault %s: %w", secretName, vaultName, err)
	}
	if bundle.Value == nil {
		return "", fmt.Errorf("secret is empty for secret %s in vault %s: %w", secretName, vaultName, err)
	}
	var secretString string
	if secretKey != "" {
		secretString, err = getSecretProperty(bundle, secretKey)
		if err != nil {
			return "", fmt.Errorf("error retrieving secret property from secret %s returned from Azure Key Vault %s: %w",
				secretName, vaultName, err)
		}
	} else {
		secretString = *bundle.Value
	}
	return secretString, nil
}

func (a *azureKeyVaultSecretManager) SetSecret(vaultName, secretName string, secretValue *secretstore.SecretValue) error {
	keyClient, err := getSecretOpsClient(vaultName)
	if err != nil {
		return fmt.Errorf("unable to create key ops client: %w", err)
	}
	secretString := secretValue.ToString()
	params := azsecrets.SetSecretParameters{
		Value: &secretString,
	}
	_, err = keyClient.SetSecret(context.TODO(), secretName, params, nil)

	if err != nil {
		return fmt.Errorf("unable to create key ops client: %w", err)
	}

	return nil
}

func getSecretPropertyMap(v azsecrets.GetSecretResponse) (map[string]string, error) {
	m := make(map[string]string)
	secretString := *v.Value
	secretBytes := []byte(secretString)
	err := json.Unmarshal(secretBytes, &m)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling GCP secrets manager secret payload in to map[string]string: %w", err)
	}
	return m, nil
}

func getSecretProperty(v azsecrets.GetSecretResponse, propertyName string) (string, error) {
	m, err := getSecretPropertyMap(v)
	if err != nil {
		return "", fmt.Errorf("error reading property %s from secret JSON object: %w", propertyName, err)
	}
	return m[propertyName], nil
}

func getSecretOpsClient(vaultName string) (*azsecrets.Client, error) {
	vaultURL, err := url.Parse(fmt.Sprintf("https://%s.vault.azure.net", vaultName))
	if err != nil {
		return nil, fmt.Errorf("error resolving url for Azure Key Vault %s: %w", vaultName, err)
	}
	cred, err := azureiam.GetKeyvaultCredentials()
	if err != nil {
		return nil, fmt.Errorf("unable to create key vault credentials: %w", err)
	}
	return azsecrets.NewClient(vaultURL.String(), cred, nil)
}
