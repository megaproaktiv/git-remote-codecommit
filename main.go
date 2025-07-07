// Oriinal Message from Python app:
// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"). You
// may not use this file except in compliance with the License. A copy of
// the License is located at
//
//     http://aws.amazon.com/apache2.0/
//
// or in the "license" file accompanying this file. This file is
// distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF
// ANY KIND, either express or implied. See the License for the specific
// language governing permissions and limitations under the License.

package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/codecommit"
)

// Custom error types
type FormatError struct {
	Message string
}

func (e FormatError) Error() string {
	return e.Message
}

type ProfileNotFoundError struct {
	Message string
}

func (e ProfileNotFoundError) Error() string {
	return e.Message
}

type RegionNotFoundError struct {
	Message string
}

func (e RegionNotFoundError) Error() string {
	return e.Message
}

type RegionNotAvailableError struct {
	Message string
}

func (e RegionNotAvailableError) Error() string {
	return e.Message
}

type CredentialsNotFoundError struct {
	Message string
}

func (e CredentialsNotFoundError) Error() string {
	return e.Message
}

// Context holds repository information derived from git's remote url and AWS profile
type Context struct {
	Config      aws.Config
	Repository  string
	Version     string
	Region      string
	Credentials aws.Credentials
}

// FromURL parses repository information from a git url
func (c *Context) FromURL(remoteURL string) error {
	// Handle the codecommit::region:// format
	if strings.HasPrefix(remoteURL, "codecommit::") {
		// Extract region and the rest of the URL
		parts := strings.SplitN(remoteURL, "::", 2)
		if len(parts) != 2 {
			return FormatError{
				Message: fmt.Sprintf("The following URL is malformed: %s. A URL must be in one of the two following formats: codecommit://<profile>@<repository> or codecommit::<region>://<profile>@<repository>", remoteURL),
			}
}

		// Parse the second part which should be "region://profile@repository"
		secondPart := parts[1]
		parsedURL, err := url.Parse(secondPart)
		if err != nil {
			return FormatError{
				Message: fmt.Sprintf("The following URL is malformed: %s. A URL must be in one of the two following formats: codecommit://<profile>@<repository> or codecommit::<region>://<profile>@<repository>", remoteURL),
			}
}

		if parsedURL.Scheme == "" || parsedURL.Host == "" {
			return FormatError{
				Message: fmt.Sprintf("The following URL is malformed: %s. A URL must be in one of the two following formats: codecommit://<profile>@<repository> or codecommit::<region>://<profile>@<repository>", remoteURL),
			}
}

		region := parsedURL.Scheme
		profile := "default"
repository := parsedURL.Host

		// Parse profile from URL - check User info first, then fallback to Host parsing
		if parsedURL.User != nil {
			profile = parsedURL.User.Username()
		} else if strings.Contains(parsedURL.Host, "@") {
			parts := strings.SplitN(parsedURL.Host, "@", 2)
			profile = parts[0]
			repository = parts[1]
}

		// Validate region availability for CodeCommit
		if !isRegionAvailable(region) {
			return RegionNotAvailableError{
				Message: fmt.Sprintf("The following AWS Region is not available for use with AWS CodeCommit: %s. For more information about CodeCommit's availability in AWS Regions, see the AWS CodeCommit User Guide.", region),
			}
}

		// Create AWS config
		ctx := context.TODO()
		cfg, err := config.LoadDefaultConfig(ctx, config.WithSharedConfigProfile(profile), config.WithRegion(region))
		if err != nil {
			return ProfileNotFoundError{
				Message: fmt.Sprintf("The following profile was not found: %s. Either use an available profile, or create an AWS CLI profile to use and then try again. For more information, see Configure an AWS CLI Profile in the AWS CLI User Guide.", profile),
			}
}

		// Get credentials
		creds, err := cfg.Credentials.Retrieve(ctx)
		if err != nil {
			return CredentialsNotFoundError{
				Message: fmt.Sprintf("The following profile does not have credentials configured: %s. You must configure the access key and secret key for the profile. For more information, see Configure an AWS CLI Profile in the AWS CLI User Guide.", profile),
			}
}

		c.Config = cfg
		c.Repository = repository
		c.Version = "v1"
		c.Region = region
c.Credentials = creds

		return nil
}

	// Handle the standard URL formats
	parsedURL, err := url.Parse(remoteURL)
	if err != nil {
		return FormatError{
			Message: fmt.Sprintf("The following URL is malformed: %s. A URL must be in one of the two following formats: codecommit://<profile>@<repository> or codecommit::<region>://<profile>@<repository>", remoteURL),
		}
	}

	if parsedURL.Scheme == "" || parsedURL.Host == "" {
		return FormatError{
			Message: fmt.Sprintf("The following URL is malformed: %s. A URL must be in one of the two following formats: codecommit://<profile>@<repository> or codecommit::<region>://<profile>@<repository>", remoteURL),
		}
	}

	profile := "default"
	repository := parsedURL.Host

	// Parse profile from URL - check User info first, then fallback to Host parsing
	if parsedURL.User != nil {
		profile = parsedURL.User.Username()
	} else if strings.Contains(parsedURL.Host, "@") {
		parts := strings.SplitN(parsedURL.Host, "@", 2)
		profile = parts[0]
		repository = parts[1]
	}

	// Create AWS config
	ctx := context.TODO()
	cfg, err := config.LoadDefaultConfig(ctx, config.WithSharedConfigProfile(profile))
	if err != nil {
		return ProfileNotFoundError{
			Message: fmt.Sprintf("The following profile was not found: %s. Either use an available profile, or create an AWS CLI profile to use and then try again. For more information, see Configure an AWS CLI Profile in the AWS CLI User Guide.", profile),
		}
	}

	var region string

	// Determine region based on URL scheme
	if parsedURL.Scheme == "codecommit" {
		region = cfg.Region
		if region == "" {
			return RegionNotFoundError{
				Message: fmt.Sprintf("The following profile does not have an AWS Region: %s. You must set an AWS Region for this profile. For more information, see Configure An AWS CLI Profile in the AWS CLI User Guide.", profile),
			}
		}
	} else {
		// Check if scheme is a region pattern (e.g., us-east-1)
		regionPattern := regexp.MustCompile(`^[a-z]{2}-\w*.*-\d{1}`)
		if regionPattern.MatchString(parsedURL.Scheme) {
			region = parsedURL.Scheme
			// Update config with the specified region
			cfg.Region = region
		} else {
			return FormatError{
				Message: fmt.Sprintf("The following URL is malformed: %s. A URL must be in one of the two following formats: codecommit://<profile>@<repository> or codecommit::<region>://<profile>@<repository>", remoteURL),
			}
		}
	}

	// Validate region availability for CodeCommit
	if !isRegionAvailable(region) {
		return RegionNotAvailableError{
			Message: fmt.Sprintf("The following AWS Region is not available for use with AWS CodeCommit: %s. For more information about CodeCommit's availability in AWS Regions, see the AWS CodeCommit User Guide.", region),
		}
	}

	// Get credentials
	creds, err := cfg.Credentials.Retrieve(ctx)
	if err != nil {
		return CredentialsNotFoundError{
			Message: fmt.Sprintf("The following profile does not have credentials configured: %s. You must configure the access key and secret key for the profile. For more information, see Configure an AWS CLI Profile in the AWS CLI User Guide.", profile),
		}
	}

	c.Config = cfg
	c.Repository = repository
	c.Version = "v1"
	c.Region = region
	c.Credentials = creds

	return nil
}

// isRegionAvailable checks if the region is available for CodeCommit
func isRegionAvailable(region string) bool {
	// Create a temporary config to check if CodeCommit is available in the region
	ctx := context.TODO()
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return false
}

	// Try to create a CodeCommit client to validate the region
	client := codecommit.NewFromConfig(cfg)
	if client == nil {
		return false
}

	// List of known CodeCommit regions (as of 2024)
	knownRegions := map[string]bool{
		"us-east-1":      true,
		"us-east-2":      true,
		"us-west-1":      true,
		"us-west-2":      true,
		"eu-west-1":      true,
		"eu-west-2":      true,
		"eu-west-3":      true,
		"eu-central-1":   true,
		"eu-north-1":     true,
		"ap-southeast-1": true,
		"ap-southeast-2": true,
		"ap-northeast-1": true,
		"ap-northeast-2": true,
		"ap-south-1":     true,
		"ca-central-1":   true,
		"sa-east-1":      true,
		"cn-north-1":     true,
		"cn-northwest-1": true,
		"us-gov-west-1":  true,
		"us-gov-east-1":  true,
}

	return knownRegions[region]
}

// websiteDomainMapping returns the appropriate domain for the region
func websiteDomainMapping(region string) string {
	if region == "cn-north-1" || region == "cn-northwest-1" {
		return "amazonaws.com.cn"
	}
	return "amazonaws.com"
}

// gitURL provides the signed URL for pushing and pulling from CodeCommit
func gitURL(repository, version, region string, creds aws.Credentials) (string, error) {
	hostname := os.Getenv("CODE_COMMIT_ENDPOINT")
	if hostname == "" {
		hostname = fmt.Sprintf("git-codecommit.%s.%s", region, websiteDomainMapping(region))
	}

	path := fmt.Sprintf("/%s/repos/%s", version, repository)

	token := ""
	if creds.SessionToken != "" {
		token = "%" + creds.SessionToken
	}

	username := url.QueryEscape(creds.AccessKeyID + token)
	signature := sign(hostname, path, region, creds)

	return fmt.Sprintf("https://%s:%s@%s%s", username, signature, hostname, path), nil
}

// timeNow is a variable that can be mocked for testing
var timeNow = time.Now

// sign provides a SigV4 signature for a CodeCommit URL
func sign(hostname, path, region string, creds aws.Credentials) string {
timestamp := timeNow().UTC().Format("20060102T150405")

	// Create canonical request
canonicalRequest := fmt.Sprintf("GIT\n%s\n\nhost:%s\n\nhost\n", path, hostname)

	// Create string to sign
	algorithm := "AWS4-HMAC-SHA256"
	credentialScope := fmt.Sprintf("%s/%s/codecommit/aws4_request", timestamp[:8], region)
stringToSign := fmt.Sprintf("%s\n%s\n%s\n%s", algorithm, timestamp, credentialScope, hashSHA256(canonicalRequest))

	// Calculate signature
	dateKey := hmacSHA256([]byte("AWS4"+creds.SecretAccessKey), timestamp[:8])
	dateRegionKey := hmacSHA256(dateKey, region)
	dateRegionServiceKey := hmacSHA256(dateRegionKey, "codecommit")
	signingKey := hmacSHA256(dateRegionServiceKey, "aws4_request")
signature := hex.EncodeToString(hmacSHA256(signingKey, stringToSign))

	return fmt.Sprintf("%sZ%s", timestamp, signature)
}

// hashSHA256 returns the SHA256 hash of the input string
func hashSHA256(input string) string {
	hash := sha256.Sum256([]byte(input))
	return hex.EncodeToString(hash[:])
}

// hmacSHA256 returns the HMAC-SHA256 of the input
func hmacSHA256(key []byte, input string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(input))
	return h.Sum(nil)
}

// errorExit prints error message and exits
func errorExit(msg string) {
	fmt.Fprintf(os.Stderr, "%s\n", msg)
	os.Exit(1)
}

func main() {
	if len(os.Args) < 3 {
		errorExit("Too few arguments. This hook requires the git command and remote.")
	}

	if len(os.Args) > 3 {
		errorExit(fmt.Sprintf("Too many arguments. Hook only accepts the git command and remote, but argv was: '%s'", strings.Join(os.Args, "', '")))
	}

	gitCmd := os.Args[1]
	remoteURL := os.Args[2]

	context := &Context{}
	if err := context.FromURL(remoteURL); err != nil {
		errorExit(err.Error())
	}

	authenticatedURL, err := gitURL(context.Repository, context.Version, context.Region, context.Credentials)
	if err != nil {
		errorExit(fmt.Sprintf("Failed to generate authenticated URL: %v", err))
	}

	// Execute git remote-http with the authenticated URL
	cmd := exec.Command("git", "remote-http", gitCmd, authenticatedURL)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	if err := cmd.Run(); err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			os.Exit(exitError.ExitCode())
		}
		errorExit(fmt.Sprintf("Failed to execute git remote-http: %v", err))
	}
}
