//go:build integration
// +build integration

package awssystemmanager_test

import (
	"testing"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/jenkins-x-plugins/secretfacade/pkg/secretstore"
	"github.com/jenkins-x-plugins/secretfacade/pkg/secretstore/awssystemmanager"
	"github.com/stretchr/testify/assert"
)

func TestGetAwsSystemManager(t *testing.T) {
	s, err := session.NewSession()
	assert.NoError(t, err)
	mgr := awssystemmanager.NewAwsSystemManager(s)
	secret, err := mgr.GetSecret("ap-southeast-2", "prod/db/creds", "")
	assert.NoError(t, err)
	assert.NotEmpty(t, secret)
}

func TestSetAwsSecretManager(t *testing.T) {
	s, err := session.NewSession()
	assert.NoError(t, err)
	mgr := awssystemmanager.NewAwsSystemManager(s)
	err = mgr.SetSecret("ap-southeast-2", "dev/db/creds", &secretstore.SecretValue{Value: "supersecret"})
	assert.NoError(t, err)
}
