//go:build integration
// +build integration

package awssecretsmanager_test

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/config"
	"testing"

	"github.com/jenkins-x-plugins/secretfacade/pkg/secretstore"
	"github.com/jenkins-x-plugins/secretfacade/pkg/secretstore/awssecretsmanager"
	"github.com/stretchr/testify/assert"
)

func TestGetAwsSecretManager(t *testing.T) {
	cfg, err := config.LoadDefaultConfig(context.TODO())
	assert.NoError(t, err)
	mgr := awssecretsmanager.NewAwsSecretManager(&cfg)
	secret, err := mgr.GetSecret("ap-southeast-2", "prod/db/creds", "")
	assert.NoError(t, err)
	assert.NotEmpty(t, secret)
}

func TestSetAwsSecretManager(t *testing.T) {
	cfg, err := config.LoadDefaultConfig(context.TODO())
	assert.NoError(t, err)
	mgr := awssecretsmanager.NewAwsSecretManager(&cfg)
	err = mgr.SetSecret("ap-southeast-2", "dev/db/creds", &secretstore.SecretValue{Value: "supersecret"})
	assert.NoError(t, err)
}
