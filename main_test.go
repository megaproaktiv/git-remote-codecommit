package main

import (
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
)

const (
	testRegion    = "us-west-2"
	testRepo      = "test_repo"
	testVersion   = "v1"
	testAccessKey = "access"
	testSecretKey = "secret"
	testToken     = "token"
)

// Test timestamp: 2017-12-24 11:53:20 UTC
var testTimestamp = time.Date(2017, 12, 24, 11, 53, 20, 0, time.UTC)

// Expected values from the Python test
const (
	expectedURL          = "https://access:20171224T115320Zb6df2d758a8023b2f000a546417007b65494f3ce8ad0300fd45fcfa173f1959a@git-codecommit.us-west-2.amazonaws.com/v1/repos/test_repo"
	expectedURLWithToken = "https://access%25token:20171224T115320Zb6df2d758a8023b2f000a546417007b65494f3ce8ad0300fd45fcfa173f1959a@git-codecommit.us-west-2.amazonaws.com/v1/repos/test_repo"
	expectedSig          = "20171224T115320Zb6df2d758a8023b2f000a546417007b65494f3ce8ad0300fd45fcfa173f1959a"
	expectedURLOverride  = "https://access:20171224T115320Za14a37a53035bbceb6e1748247b143124fe7326cdffd3d418236a592ce6158a0@land.called.honahlee/v1/repos/test_repo"
)

// Mock time.Now for consistent testing
var originalTimeNow = timeNow

func mockTimeNow() time.Time {
	return testTimestamp
}

func TestGitURL(t *testing.T) {
	// Mock timeNow
	defer func() { timeNow = originalTimeNow }()
	timeNow = mockTimeNow

	creds := aws.Credentials{
		AccessKeyID:     testAccessKey,
		SecretAccessKey: testSecretKey,
	}

	url, err := gitURL(testRepo, testVersion, testRegion, creds)
	if err != nil {
		t.Fatalf("gitURL returned error: %v", err)
	}

	if url != expectedURL {
		t.Errorf("Expected URL: %s\nGot URL: %s", expectedURL, url)
	}
}

func TestGitURLWithToken(t *testing.T) {
	// Mock timeNow
	defer func() { timeNow = originalTimeNow }()
	timeNow = mockTimeNow

	creds := aws.Credentials{
		AccessKeyID:     testAccessKey,
		SecretAccessKey: testSecretKey,
		SessionToken:    testToken,
	}

	url, err := gitURL(testRepo, testVersion, testRegion, creds)
	if err != nil {
		t.Fatalf("gitURL returned error: %v", err)
	}

	if url != expectedURLWithToken {
		t.Errorf("Expected URL with token: %s\nGot URL: %s", expectedURLWithToken, url)
	}
}

func TestGitURLWithOverride(t *testing.T) {
	// Mock timeNow
	defer func() { timeNow = originalTimeNow }()
	timeNow = mockTimeNow

	// Set environment variable
	originalEndpoint := os.Getenv("CODE_COMMIT_ENDPOINT")
	os.Setenv("CODE_COMMIT_ENDPOINT", "land.called.honahlee")
	defer func() {
		if originalEndpoint == "" {
			os.Unsetenv("CODE_COMMIT_ENDPOINT")
		} else {
			os.Setenv("CODE_COMMIT_ENDPOINT", originalEndpoint)
		}
	}()

	creds := aws.Credentials{
		AccessKeyID:     testAccessKey,
		SecretAccessKey: testSecretKey,
	}

	url, err := gitURL(testRepo, testVersion, testRegion, creds)
	if err != nil {
		t.Fatalf("gitURL returned error: %v", err)
	}

	if url != expectedURLOverride {
		t.Errorf("Expected URL with override: %s\nGot URL: %s", expectedURLOverride, url)
	}
}

func TestSign(t *testing.T) {
	// Mock timeNow
	defer func() { timeNow = originalTimeNow }()
	timeNow = mockTimeNow

	creds := aws.Credentials{
		AccessKeyID:     testAccessKey,
		SecretAccessKey: testSecretKey,
	}

	hostname := "git-codecommit.us-west-2.amazonaws.com"
	path := "/v1/repos/test_repo"

	signature := sign(hostname, path, testRegion, creds)

	if signature != expectedSig {
		t.Errorf("Expected signature: %s\nGot signature: %s", expectedSig, signature)
	}
}
