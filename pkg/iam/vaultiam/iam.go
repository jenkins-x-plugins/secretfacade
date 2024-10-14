package vaultiam

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/hashicorp/vault/api"
	"github.com/jenkins-x/jx-logging/v3/pkg/log"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	secretNamespace       = "secret-infra"
	externalSecretsPrefix = "kubernetes-external-secrets-token" //nolint:gosec
)

type VaultCreds struct {
	Token      string
	CaCertPath string
}

func NewEnvironmentCreds() (VaultCreds, error) {
	token, ok := os.LookupEnv("VAULT_TOKEN")
	// Skip the check for vault related environment variables if using external vault
	if !ok || token == "" {
		return VaultCreds{}, fmt.Errorf("unable to find VAULT_TOKEN on environment")
	}

	caCertPath := os.Getenv("VAULT_CACERT")

	return VaultCreds{
		Token:      token,
		CaCertPath: caCertPath,
	}, nil
}

func NewExternalSecretCreds(client *api.Client, kubeClient kubernetes.Interface) (VaultCreds, error) {
	token, err := getTokenForExternalVault(client, kubeClient)
	if err != nil {
		return VaultCreds{}, fmt.Errorf("error getting client token for external vault: %w", err)
	}

	caCertPath := os.Getenv("VAULT_CACERT")

	return VaultCreds{
		Token:      token,
		CaCertPath: caCertPath,
	}, nil
}

// Taken from https://www.vaultproject.io/docs/auth/kubernetes#code-example
func getTokenForExternalVault(client *api.Client, kubeClient kubernetes.Interface) (string, error) {
	vaultMountPoint := os.Getenv("JX_VAULT_MOUNT_POINT")
	if vaultMountPoint == "" {
		vaultMountPoint = "kubernetes"
		log.Logger().Debug("Setting vault mount point to kubernetes as JX_VAULT_MOUNT_POINT is missing")
	}
	vaultRole := os.Getenv("JX_VAULT_ROLE")
	if vaultRole == "" {
		vaultRole = "jx-vault"
		log.Logger().Debug("Setting vault role to jx-vault as JX_VAULT_ROLE is missing")
	}

	secrets, err := kubeClient.CoreV1().Secrets(secretNamespace).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return "", fmt.Errorf("error listing secrets: %w", err)
	}

	if len(secrets.Items) == 0 {
		return "", fmt.Errorf("no secrets found in %s namespace", secretNamespace)
	}

	var secretName string
	for k := range secrets.Items {
		name := secrets.Items[k].Name
		if strings.HasPrefix(name, externalSecretsPrefix) {
			secretName = name
			break
		}
	}

	if secretName == "" {
		return "", fmt.Errorf("could not find secret with prefix %s in %s namespace", externalSecretsPrefix, secretNamespace)
	}

	secret, err := kubeClient.CoreV1().Secrets(secretNamespace).Get(context.TODO(), secretName, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("error getting secret %s: %w", secretName, err)
	}

	if secret.Data == nil {
		return "", fmt.Errorf("data field in secret %s is missing", secretName)
	}

	token := string(secret.Data["token"])

	if token == "" {
		return "", fmt.Errorf("could not retrieve jwt token from secret %s", secretName)
	}

	params := map[string]interface{}{
		"jwt":  token,
		"role": vaultRole,
	}
	// log in to Vault's Kubernetes auth method
	resp, err := client.Logical().Write("auth/"+vaultMountPoint+"/login", params)
	if err != nil {
		return "", fmt.Errorf("unable to log in with Kubernetes auth at mount point %s using role %s: %w", vaultMountPoint, vaultRole, err)
	}
	if resp == nil || resp.Auth == nil || resp.Auth.ClientToken == "" {
		return "", fmt.Errorf("login response did not return client token")
	}
	return resp.Auth.ClientToken, nil
}
