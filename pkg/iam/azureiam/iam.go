package azureiam

import (
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

var keyvaultCredentials azcore.TokenCredential

// GetKeyvaultCredentials gets a TokenCredential for use with Key Vault
// keys and secrets. Note that Key Vault *Vaults* are managed by Azure Resource
// Manager.
func GetKeyvaultCredentials() (azcore.TokenCredential, error) {
	if keyvaultCredentials != nil {
		return keyvaultCredentials, nil
	}
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, err
	}
	keyvaultCredentials = cred
	return keyvaultCredentials, err
}
