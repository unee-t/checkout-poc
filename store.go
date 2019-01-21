package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/apex/log"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/ec2rolecreds"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/pkg/errors"
	"gocloud.dev/blob"
	"gocloud.dev/blob/s3blob"
)

func save(key string, payload string) (err error) {
	ctx := context.Background()
	b, err := setupAWS(ctx, bucket)
	if err != nil {
		log.WithError(err).Error("failed to setup bucket")
		return err
	}
	err = b.WriteAll(ctx, key, []byte(payload), nil)
	if err != nil {
		log.WithError(err).Error("failed to write to bucket")
		return err
	}
	log.Infof("Wrote out to s3://%s/%s", bucket, key)
	return nil
}

func load(key string) (payload string, err error) {
	ctx := context.Background()
	b, err := setupAWS(ctx, bucket)
	if err != nil {
		return payload, errors.Wrap(err, "bucket setup")
	}

	r, err := b.NewReader(ctx, key, nil)
	if err != nil {
		return payload, errors.Wrap(err, "no reader")
	}

	// https://godoc.org/gocloud.dev/blob#Bucket.ReadAll
	payloadbytes, err := ioutil.ReadAll(r)
	if err != nil {
		return payload, errors.Wrap(err, "failed to read")
	}
	payload = string(payloadbytes)

	log.Infof("Read from to s3://%s/%s = %q", bucket, key, payload)

	return

}

func del(key string) (err error) {
	if key == "" {
		return fmt.Errorf("Empty key")
	}
	ctx := context.Background()
	b, err := setupAWS(ctx, bucket)
	if err != nil {
		log.WithError(err).Error("failed to setup bucket")
		return err
	}
	err = b.Delete(ctx, key)
	if err != nil {
		log.WithError(err).Error("failed to delete")
	}
	return
}

// Using the AWS cloud
func setupAWS(ctx context.Context, bucket string) (b *blob.Bucket, err error) {
	sess := session.New()
	profile := os.Getenv("AWS_PROFILE")
	if profile == "" {
		profile = "uneet-dev"
	}
	creds := credentials.NewChainCredentials(
		[]credentials.Provider{
			// If you want to set AWS_ACCESS_KEY_ID & AWS_SECRET_ACCESS_KEY envs
			&credentials.EnvProvider{},
			// For when I use cmd/
			&credentials.SharedCredentialsProvider{Filename: "", Profile: profile},
			// IIUC, this is how IAM role is assumed in the Lambda env
			&ec2rolecreds.EC2RoleProvider{Client: ec2metadata.New(sess)},
		})
	cfg := &aws.Config{
		Region:                        aws.String("ap-southeast-1"),
		Credentials:                   creds,
		CredentialsChainVerboseErrors: aws.Bool(true),
	}
	sess, err = session.NewSession(cfg)
	b, err = s3blob.OpenBucket(ctx, sess, bucket, nil)
	return
}
