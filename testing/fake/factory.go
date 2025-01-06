package fake

import (
	"github.com/jenkins-x-plugins/secretfacade/pkg/secretstore"
)

type SecretManagerFactory struct {
	secretStore *SecretStore
}

func (f *SecretManagerFactory) NewSecretManager(_ secretstore.Type) (secretstore.Interface, error) {
	if f.secretStore == nil {
		f.secretStore = NewFakeSecretStore()
	}
	return f.secretStore, nil
}

func (f SecretManagerFactory) GetSecretStore() *SecretStore {
	return f.secretStore
}
