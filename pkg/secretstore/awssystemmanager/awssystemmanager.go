package awssystemmanager

import (
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ssm"
	"github.com/jenkins-x-plugins/secretfacade/pkg/secretstore"
)

func NewAwsSystemManager(session *session.Session) secretstore.Interface {
	return awsSystemManager{session}
}

type awsSystemManager struct {
	session *session.Session
}

func (a awsSystemManager) GetSecret(location, secretName, _ string) (string, error) {
	input := &ssm.GetParameterInput{
		Name: aws.String(secretName),
	}
	mgr := ssm.New(a.session, aws.NewConfig().WithRegion(location))
	mgr.Config.Region = &location
	result, err := mgr.GetParameter(input)
	if err != nil {
		return "", fmt.Errorf("error retrieving secret from aws parameter store: %w", err)
	}
	return result.String(), nil
}

func (a awsSystemManager) SetSecret(location, secretName string, secretValue *secretstore.SecretValue) error {
	input := &ssm.PutParameterInput{
		Name:  &secretName,
		Value: &secretValue.Value,
	}
	mgr := ssm.New(a.session, aws.NewConfig().WithRegion(location))
	mgr.Config.Region = &location

	_, err := mgr.PutParameter(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			if aerr.Code() == ssm.ErrCodeParameterAlreadyExists {
				return fmt.Errorf("Secret Already Exists: %w", err)
			}
			return fmt.Errorf("error setting secret for aws parameter store: %w", err)
		}
	}
	return nil
}
