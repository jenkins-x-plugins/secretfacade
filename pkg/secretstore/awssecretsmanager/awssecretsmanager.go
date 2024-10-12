package awssecretsmanager

import (
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/jenkins-x-plugins/secretfacade/pkg/secretstore"
)

func NewAwsSecretManager(session *session.Session) secretstore.Interface {
	return awsSecretsManager{session}
}

type awsSecretsManager struct {
	session *session.Session
}

func (a awsSecretsManager) GetSecret(location, secretName, propertyName string) (string, error) {
	secret, err := getExistingSecret(a.session, location, secretName)
	if err != nil {
		return "", fmt.Errorf("error retrieving existing secret for aws secret manager: : %w", err)
	}

	if propertyName != "" {
		secretString, err := getSecretProperty(secret, propertyName)
		if err != nil {
			return "", fmt.Errorf("error retrieving secret property from secret %s returned from AWS secrets manager: : %w", secretName, err)
		}
		return secretString, nil
	}

	return *secret.SecretString, nil
}

func getSecretProperty(s *secretsmanager.GetSecretValueOutput, propertyName string) (string, error) {
	m, err := getSecretPropertyMap(s.SecretString)
	if err != nil {
		return "", fmt.Errorf("error reading property %s from secret JSON object: %w", propertyName, err)
	}
	return m[propertyName], nil
}

func (a awsSecretsManager) SetSecret(location, secretName string, secretValue *secretstore.SecretValue) (err error) {
	// CreateSecret
	err = createSecret(a.session, location, secretName, *secretValue)
	if err != nil {
		// Don't return if secret already exists.
		if err.(awserr.Error).Code() != secretsmanager.ErrCodeResourceExistsException {
			return fmt.Errorf("error creating new secret for aws secret manager: : %w", err)
		}
	}

	// GetSecretValue + PutSecretValue/UpdateSecret
	// Get, Merge and Update
	secret, err := getExistingSecret(a.session, location, secretName)
	if err != nil {
		return fmt.Errorf("error retreiving existing secret for aws secret manager: : %w", err)
	}
	var existingSecretProps map[string]string
	// FIXME: If secretValue is Simple, AND then secret.SecretString is Simple.
	// getSecretPropertyMap fails
	if secretValue.Value == "" && secretValue.PropertyValues != nil {
		existingSecretProps, err = getSecretPropertyMap(secret.SecretString)
		if err != nil {
			return fmt.Errorf("error parsing existing secret: : %w", err)
		}
	}

	err = updateSecret(a.session, secret, secretValue.MergeExistingSecret(existingSecretProps), location)
	if err != nil {
		return fmt.Errorf("error updating existing secret for aws secret manager: : %w", err)
	}

	return nil
}

func updateSecret(session *session.Session, secret *secretsmanager.GetSecretValueOutput, newValue, location string) (err error) {
	input := &secretsmanager.PutSecretValueInput{
		SecretId:     secret.ARN,
		SecretString: aws.String(newValue),
	}
	svc := secretsmanager.New(session, aws.NewConfig().WithRegion(location))
	_, err = svc.PutSecretValue(input)
	if err != nil {
		return fmt.Errorf("error updating existing secret: : %w", err)
	}
	return nil
}

func getExistingSecret(session *session.Session, location, secretName string) (secret *secretsmanager.GetSecretValueOutput, err error) {
	input := &secretsmanager.GetSecretValueInput{
		SecretId: &secretName,
	}
	svc := secretsmanager.New(session, aws.NewConfig().WithRegion(location))
	secret, err = svc.GetSecretValue(input)
	if err != nil {
		return
	}
	return
}

func createSecret(session *session.Session, location, secretName string, secretValue secretstore.SecretValue) (err error) {
	input := &secretsmanager.CreateSecretInput{
		Name:         &secretName,
		SecretString: aws.String(secretValue.ToString()),
	}
	svc := secretsmanager.New(session, aws.NewConfig().WithRegion(location))
	_, err = svc.CreateSecret(input)
	if err != nil {
		return err
	}
	return nil
}

func getSecretPropertyMap(value *string) (map[string]string, error) {
	m := make(map[string]string)
	err := json.Unmarshal([]byte(*value), &m)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling AWS secrets manager secret payload in to map[string]string: %w", err)
	}
	return m, nil
}
