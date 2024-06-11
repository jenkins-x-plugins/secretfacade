package vaultsecrets_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/jenkins-x-plugins/secretfacade/pkg/iam/vaultiam"
	"github.com/jenkins-x-plugins/secretfacade/pkg/secretstore/vaultsecrets"
	"github.com/stretchr/testify/assert"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/hashicorp/vault/api"
	vaulthttp "github.com/hashicorp/vault/http"
	"github.com/hashicorp/vault/vault"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	kubeauth "github.com/hashicorp/vault-plugin-auth-kubernetes"
	"github.com/hashicorp/vault/sdk/logical"
)

// Presently, all we test is that we can get token from vault using kubernetes service account token.
// Running into issues of TLS when I try to run tests for setting and getting secrets, but it seems related to testing and not the code
// ToDo: Add tests for setting and getting secrets

// JWT generated from here: https://jwt.io/
// After decoding, the payload looks like this: (the uid is used by the test server)
/*
{
  "iss": "kubernetes/serviceaccount",
  "kubernetes.io/serviceaccount/namespace": "secret-infra",
  "kubernetes.io/serviceaccount/secret.name": "kubernetes-external-secrets-token-nhl6b",
  "kubernetes.io/serviceaccount/service-account.name": "default",
  "kubernetes.io/serviceaccount/service-account.uid": "424d91ce-20e3-48a2-b1e5-394e6a0c1813",
  "sub": "system:serviceaccount:kube-system:default"
}
*/
const testJWT = "ewogICJhbGciOiAiUlMyNTYiLAogICJraWQiOiAiaW45SFpIU0hEYmpnUEZxa2MxYVNJYjhvNmtHNFc1M09MMXNzd0JhVkxWYyIKfQ.ewogICJpc3MiOiAia3ViZXJuZXRlcy9zZXJ2aWNlYWNjb3VudCIsCiAgImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvbmFtZXNwYWNlIjogInNlY3JldC1pbmZyYSIsCiAgImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VjcmV0Lm5hbWUiOiAia3ViZXJuZXRlcy1leHRlcm5hbC1zZWNyZXRzLXRva2VuLW5obDZiIiwKICAia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZXJ2aWNlLWFjY291bnQubmFtZSI6ICJkZWZhdWx0IiwKICAia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZXJ2aWNlLWFjY291bnQudWlkIjogIjQyNGQ5MWNlLTIwZTMtNDhhMi1iMWU1LTM5NGU2YTBjMTgxMyIsCiAgInN1YiI6ICJzeXN0ZW06c2VydmljZWFjY291bnQ6a3ViZS1zeXN0ZW06ZGVmYXVsdCIKfQ.d_M2SR-geb6IKgD3_o3Bp4ndpUA_v3_NC1sIXrWY7j77Kbqe9imsQP91qAiMhq16ANyDWQ4cz2255_72RvOxpGCpwRT5NNxDfdVQxFuqHwYRsW3u8Olddjj_4bqIWlfd1Osh8GutnOswEll53aKzmGcvDk2wAD0PMNZhSBm_3-_V85UZtuhkPVHyuzP4__CRe1TC2P7kGWR6-uUp0A8B2xsRP2n24EOEypxIB2PiF3iv5w6dMGJ3Ans_rJaeudNjKxzXYCXptmvqC12gBh7B-U3qNpBwTd-ige2JtbyZXLEyrJhoO03ZrFaT4k8AfckG9-ZlXL66v3FrhcGqy-5vww"

func TestNewVaultSecretManager(t *testing.T) {
	os.Setenv("EXTERNAL_VAULT", "true")
	os.Setenv("JX_VAULT_MOUNT_POINT", "kubernetes")
	os.Setenv("JX_VAULT_ROLE", "role")
	kubeClient := fake.NewSimpleClientset(&corev1.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind:       "",
			APIVersion: "",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "kubernetes-external-secrets-token-xfgty",
			Namespace: "secret-infra",
		},
		Immutable: new(bool),
		Data: map[string][]byte{
			"token": []byte(testJWT),
		},
	})

	cluster := vault.NewTestCluster(t, &vault.CoreConfig{
		DevToken: "token-test",
		CredentialBackends: map[string]logical.Factory{
			"kubernetes": kubeauth.Factory,
		},
	}, &vault.TestClusterOptions{
		NumCores:    1, // Let's only start one vault instance
		HandlerFunc: vaulthttp.Handler,
	})
	cluster.Start()
	defer cluster.Cleanup()

	core := cluster.Cores[0].Core
	vault.TestWaitActive(t, core)
	client := cluster.Cores[0].Client

	err := client.Sys().EnableAuthWithOptions("kubernetes", &api.EnableAuthOptions{
		Type: "kubernetes",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Start a server to mimic kubernetes cluster
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		// Send response to be tested
		// If you decode the test json, then the value of kubernetes.io/serviceaccount/service-account.uid is 424d91ce-20e3-48a2-b1e5-394e6a0c1813
		_, _ = rw.Write([]byte(`{"status": {"authenticated": true, "user":{"uid":"424d91ce-20e3-48a2-b1e5-394e6a0c1813","username": "system:serviceaccount:secret-infra:default"}}}`))
	}))
	defer server.Close()
	// Create config
	_, err = client.Logical().Write("auth/kubernetes/config", map[string]interface{}{
		"token_reviewer_jwt": testJWT,
		"kubernetes_host":    server.URL,
		"kubernetes_ca_cert": "unittest",
	})

	if err != nil {
		t.Fatal(err)
	}

	// Create role
	_, err = client.Logical().Write("auth/kubernetes/role/role", map[string]interface{}{
		"bound_service_account_names":      "default",
		"bound_service_account_namespaces": "secret-infra",
		"policies":                         []string{"unittest"},
		"ttl":                              "1h",
	})

	if err != nil {
		t.Fatal(err)
	}

	creds, err := vaultiam.NewExternalSecretCreds(client, kubeClient)
	if err != nil {
		t.Fatal(err)
	}
	client.SetToken(creds.Token)
	_, err = vaultsecrets.NewVaultSecretManager(client)
	assert.Empty(t, err)
}
