package secretref

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

// awsBackend resolves aws-sm:// references with the official AWS SDK.
// Credentials come from the standard chain (config.LoadDefaultConfig: env
// vars, shared config, IRSA web identity, ECS/EC2 instance roles). The SDK
// itself honours AWS_ENDPOINT_URL_SECRETS_MANAGER, which is how tests point
// it at a fake.
type awsBackend struct {
	client onceValue[*secretsmanager.Client]
}

func (b *awsBackend) ensure(ctx context.Context) (*secretsmanager.Client, error) {
	return b.client.get(func() (*secretsmanager.Client, error) {
		cfg, err := awsconfig.LoadDefaultConfig(ctx)
		if err != nil {
			return nil, fmt.Errorf("load aws config: %w", err)
		}
		return secretsmanager.NewFromConfig(cfg), nil
	})
}

// awsARNRegion extracts the region from a Secrets Manager ARN
// (arn:aws:secretsmanager:<region>:<account>:secret:<name>), or "" if id is
// a plain secret name rather than an ARN.
func awsARNRegion(id string) string {
	if !strings.HasPrefix(id, "arn:") {
		return ""
	}
	parts := strings.SplitN(id, ":", 5)
	if len(parts) < 4 {
		return ""
	}
	return parts[3]
}

func (b *awsBackend) resolve(ctx context.Context, r ref) (string, error) {
	client, err := b.ensure(ctx)
	if err != nil {
		return "", err
	}
	region := r.query.Get("region")
	if region == "" {
		region = awsARNRegion(r.path)
	}
	input := &secretsmanager.GetSecretValueInput{SecretId: aws.String(r.path)}
	if vs := r.query.Get("version_stage"); vs != "" {
		input.VersionStage = aws.String(vs)
	}
	out, err := client.GetSecretValue(ctx, input, func(o *secretsmanager.Options) {
		if region != "" {
			o.Region = region
		}
	})
	if err != nil {
		return "", err
	}
	var raw string
	switch {
	case out.SecretString != nil:
		raw = *out.SecretString
	case out.SecretBinary != nil:
		raw = string(out.SecretBinary)
	default:
		return "", errors.New("empty secret value")
	}
	return jsonField(raw, r.key)
}
