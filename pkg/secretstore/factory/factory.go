package factory

import (
	"fmt"
	"os"

	"context"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/hashicorp/vault/api"
	"github.com/jenkins-x-plugins/secretfacade/pkg/iam/gcpiam"
	"github.com/jenkins-x-plugins/secretfacade/pkg/iam/kubernetesiam"
	"github.com/jenkins-x-plugins/secretfacade/pkg/iam/vaultiam"
	"github.com/jenkins-x-plugins/secretfacade/pkg/secretstore"
	"github.com/jenkins-x-plugins/secretfacade/pkg/secretstore/awssecretsmanager"
	"github.com/jenkins-x-plugins/secretfacade/pkg/secretstore/awssystemmanager"
	"github.com/jenkins-x-plugins/secretfacade/pkg/secretstore/azuresecrets"
	"github.com/jenkins-x-plugins/secretfacade/pkg/secretstore/gcpsecretsmanager"
	"github.com/jenkins-x-plugins/secretfacade/pkg/secretstore/kubernetessecrets"
	"github.com/jenkins-x-plugins/secretfacade/pkg/secretstore/vaultsecrets"
)

type SecretManagerFactory struct{}

func (smf SecretManagerFactory) NewSecretManager(storeType secretstore.Type) (secretstore.Interface, error) {
	switch storeType {
	case secretstore.SecretStoreTypeAzure:
		return azuresecrets.NewAzureKeyVaultSecretManager(), nil
	case secretstore.SecretStoreTypeGoogle:
		creds, err := gcpiam.DefaultCredentials()
		if err != nil {
			return nil, fmt.Errorf("error getting Google creds when attempting to create secret manager via factory: %w", err)
		}
		return gcpsecretsmanager.NewGcpSecretsManager(creds), nil
	case secretstore.SecretStoreTypeKubernetes:
		client, err := kubernetesiam.GetClient()
		if err != nil {
			return nil, fmt.Errorf("error getting Kubernetes creds when attempting to create secret manager via factory: %w", err)
		}
		return kubernetessecrets.NewKubernetesSecretManager(client), nil
	case secretstore.SecretStoreTypeVault:
		caCertPath := os.Getenv("VAULT_CACERT")
		config := api.Config{}
		err := config.ConfigureTLS(&api.TLSConfig{
			CACert: caCertPath,
		})
		if err != nil {
			return nil, fmt.Errorf("error configuring TLS ca cert for Hashicorp Vault API: %w", err)
		}

		// ToDo: Why are we not passing the config?
		// ToDo: Change it in another PR
		client, err := api.NewClient(nil)
		if err != nil {
			return nil, fmt.Errorf("error creating Hashicorp Vault API client: %w", err)
		}
		isExternalVault := os.Getenv("EXTERNAL_VAULT")
		if isExternalVault == "true" {
			kubeClient, err := kubernetesiam.GetClient()
			if err != nil {
				return nil, fmt.Errorf("error getting Kubernetes creds when attempting to create secret manager via factory: %w", err)
			}
			creds, err := vaultiam.NewExternalSecretCreds(client, kubeClient)
			if err != nil {
				return nil, fmt.Errorf("error getting Hashicorp Vault creds when attempting to create secret manager via factory: %w", err)
			}
			client.SetToken(creds.Token)
			return vaultsecrets.NewVaultSecretManager(client)
		}
		creds, err := vaultiam.NewEnvironmentCreds()
		if err != nil {
			return nil, fmt.Errorf("error getting Hashicorp Vault creds when attempting to create secret manager via factory: %w", err)
		}

		client.SetToken(creds.Token)
		return vaultsecrets.NewVaultSecretManager(client)
	case secretstore.SecretStoreTypeAwsASM:
		cfg, err := config.LoadDefaultConfig(context.TODO())
		if err != nil {
			return nil, fmt.Errorf("error getting AWS creds when attempting to create secret manager via factory: %w", err)
		}
		return awssecretsmanager.NewAwsSecretManager(&cfg), nil
	case secretstore.SecretStoreTypeAwsSSM:
		cfg, err := config.LoadDefaultConfig(context.TODO())
		if err != nil {
			return nil, fmt.Errorf("error getting AWS creds when attempting to create secret manager via factory: %w", err)
		}
		return awssystemmanager.NewAwsSystemManager(&cfg), nil
	}
	return nil, fmt.Errorf("unable to create manager for storeType %s", string(storeType))
}
