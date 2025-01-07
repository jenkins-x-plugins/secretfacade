package awssystemmanager

import (
	"context"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"

	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/jenkins-x-plugins/secretfacade/pkg/secretstore"
)

func NewAwsSystemManager(cfg *aws.Config) secretstore.Interface {
	return awsSystemManager{cfg}
}

type awsSystemManager struct {
	cfg *aws.Config
}

func (a awsSystemManager) GetSecret(location, secretName, _ string) (string, error) {
	input := &ssm.GetParameterInput{
		Name: aws.String(secretName),
	}
	mgr := ssm.NewFromConfig(*a.cfg, func(o *ssm.Options) {
		o.Region = location
	})
	result, err := mgr.GetParameter(context.TODO(), input)
	if err != nil {
		return "", fmt.Errorf("error retrieving secret from aws parameter store: %w", err)
	}
	return *result.Parameter.Value, nil
}

func (a awsSystemManager) SetSecret(location, secretName string, secretValue *secretstore.SecretValue) error {
	input := &ssm.PutParameterInput{
		Name:  &secretName,
		Value: &secretValue.Value,
	}
	mgr := ssm.NewFromConfig(*a.cfg, func(o *ssm.Options) {
		o.Region = location
	})

	_, err := mgr.PutParameter(context.TODO(), input)
	if err != nil {
		var alreadyExists *types.AlreadyExistsException
		if errors.As(err, &alreadyExists) {
			return fmt.Errorf("secret already exists: %w", err)
		}
		return fmt.Errorf("error setting secret for aws parameter store: %w", err)
	}
	return nil
}
