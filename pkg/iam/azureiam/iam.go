package azureiam

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/adal"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/Azure/go-autorest/autorest/azure/auth"
	"github.com/pkg/errors"
)

type Credentials interface {
	ClientID() string
	ClientSecret() string
	TenantID() string
	SubscriptionID() string
	UseManagedIdentity() bool
}

func NewEnvironmentCredentials() (Credentials, error) {
	settings, err := auth.GetSettingsFromEnvironment()
	if err != nil {
		return nil, errors.Wrap(err, "error getting Azure credentials from environment")
	}

	isMSIEnvironment := adal.MSIAvailable(context.TODO(), adal.CreateSender())
	if !isMSIEnvironment && (settings.Values[auth.ClientSecret] == "" || settings.Values[auth.ClientID] == "") {
		return nil, fmt.Errorf("no client secret or client id found on environment and not running within MSI enabled context")
	}
	useMSI := false
	if isMSIEnvironment && (settings.Values[auth.ClientSecret] == "" || settings.Values[auth.ClientID] == "") {
		useMSI = true
	}

	if useMSI {
		if settings.Values[auth.TenantID] == "" || settings.Values[auth.SubscriptionID] == "" {
			return nil, fmt.Errorf("AZURE_TENANT_ID and AZURE_SUBSCRIPTION_ID are mandatory environment variables for MSI authentication")
		}
		return &environmentCredentials{
			tenantID:           settings.Values[auth.TenantID],
			subscriptionID:     settings.Values[auth.SubscriptionID],
			clientID:           settings.Values[auth.ClientID],
			useManagedIdentity: true,
		}, nil
	}

	if settings.Values[auth.ClientID] == "" || settings.Values[auth.ClientSecret] == "" ||
		settings.Values[auth.TenantID] == "" || settings.Values[auth.SubscriptionID] == "" {
		return nil, fmt.Errorf("AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET and AZURE_SUBSCRIPTION_ID are mandatory environment variables for client credentials authentication")
	}
	return &environmentCredentials{
		clientID:           settings.Values[auth.ClientID],
		clientSecret:       settings.Values[auth.ClientSecret],
		tenantID:           settings.Values[auth.TenantID],
		subscriptionID:     settings.Values[auth.SubscriptionID],
		useManagedIdentity: false,
	}, nil
}

type environmentCredentials struct {
	clientID           string
	clientSecret       string
	tenantID           string
	subscriptionID     string
	useManagedIdentity bool
}

func (e environmentCredentials) ClientID() string {
	return e.clientID
}

func (e environmentCredentials) ClientSecret() string {
	return e.clientSecret
}

func (e environmentCredentials) TenantID() string {
	return e.tenantID
}

func (e environmentCredentials) SubscriptionID() string {
	return e.subscriptionID
}

func (e environmentCredentials) UseManagedIdentity() bool {
	return e.useManagedIdentity
}

func Environment() (*azure.Environment, error) {
	settings, err := auth.GetSettingsFromEnvironment()
	if err != nil {
		return nil, errors.Wrapf(err, "unable to determine Azure environment from environment")
	}
	return &settings.Environment, nil
}

// OAuthGrantType specifies which grant type to use.
type OAuthGrantType int

const (
	// OAuthGrantTypeServicePrincipal for client credentials flow
	OAuthGrantTypeServicePrincipal OAuthGrantType = iota
	// OAuthGrantTypeManagedIdentity for aad-pod-identity
	OAuthGrantTypeManagedIdentity
)

// GrantType returns what grant type has been configured.
func grantType(creds Credentials) OAuthGrantType {
	if creds.UseManagedIdentity() {
		return OAuthGrantTypeManagedIdentity
	}
	return OAuthGrantTypeServicePrincipal
}

var keyvaultAuthorizer autorest.Authorizer

// GetKeyvaultAuthorizer gets an OAuthTokenAuthorizer for use with Key Vault
// keys and secrets. Note that Key Vault *Vaults* are managed by Azure Resource
// Manager.
func GetKeyvaultAuthorizer(creds Credentials) (autorest.Authorizer, error) {
	if keyvaultAuthorizer != nil {
		return keyvaultAuthorizer, nil
	}

	environment, err := Environment()
	if err != nil {
		return nil, errors.Wrapf(err, "unable to determine environment")
	}
	// BUG: default value for KeyVaultEndpoint is wrong
	vaultEndpoint := strings.TrimSuffix(environment.KeyVaultEndpoint, "/")
	// BUG: alternateEndpoint replaces other endpoints in the configs below
	alternateEndpoint, _ := url.Parse(
		"https://login.windows.net/" + creds.TenantID() + "/oauth2/token")

	var a autorest.Authorizer

	switch grantType(creds) {
	case OAuthGrantTypeServicePrincipal:
		oauthconfig, err := adal.NewOAuthConfig(
			environment.ActiveDirectoryEndpoint, creds.TenantID())
		if err != nil {
			return a, err
		}
		oauthconfig.AuthorizeEndpoint = *alternateEndpoint

		token, err := adal.NewServicePrincipalToken(
			*oauthconfig, creds.ClientID(), creds.ClientSecret(), vaultEndpoint)
		if err != nil {
			return a, err
		}

		a = autorest.NewBearerAuthorizer(token)

	case OAuthGrantTypeManagedIdentity:
		token, err := adal.NewServicePrincipalTokenFromManagedIdentity(vaultEndpoint, &adal.ManagedIdentityOptions{
			ClientID: creds.ClientID(),
		})
		if err != nil {
			return nil, err
		}

		a = autorest.NewBearerAuthorizer(token)

	default:
		return a, fmt.Errorf("invalid grant type specified")
	}

	keyvaultAuthorizer = a

	return keyvaultAuthorizer, err
}
