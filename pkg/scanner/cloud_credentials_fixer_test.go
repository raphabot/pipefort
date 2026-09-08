package scanner

import (
	"strings"
	"testing"
)

// The fix for a static cloud credential is comment-only by design: the role
// ARN / workload-identity provider / federated app registration does not exist
// in the file, and inventing one would produce a workflow that fails at run
// time. The comment carries the exact replacement so the author can act on it.

func fixOnce(t *testing.T, in string) (string, int) {
	t.Helper()
	findings, err := ScanBytes(".github/workflows/deploy.yml", []byte(in))
	if err != nil {
		t.Fatalf("ScanBytes: %v", err)
	}
	var creds []Finding
	for _, f := range findings {
		if f.RuleID == RuleCloudStaticCredentials {
			creds = append(creds, f)
		}
	}
	if len(creds) == 0 {
		t.Fatalf("fixture produced no %s findings", RuleCloudStaticCredentials)
	}
	out, n, err := FixBytes([]byte(in), creds)
	if err != nil {
		t.Fatalf("FixBytes: %v", err)
	}
	if out == nil {
		return in, n
	}
	return string(out), n
}

func TestFixCloudStaticCredentialsAnnotatesLoginAction(t *testing.T) {
	const in = `on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
`
	out, n := fixOnce(t, in)
	if n != 1 {
		t.Fatalf("applied %d fixes, want 1", n)
	}
	if !strings.Contains(out, "pipefort") {
		t.Errorf("output carries no pipefort marker comment:\n%s", out)
	}
	if !strings.Contains(out, "role-to-assume") {
		t.Errorf("comment should name the AWS replacement:\n%s", out)
	}
	// The workflow must still parse, and the credential must still be there:
	// this fix advises, it does not break the deploy.
	if !strings.Contains(out, "aws-access-key-id") {
		t.Errorf("fix removed the credential instead of annotating it:\n%s", out)
	}
	if _, err := ScanBytes(".github/workflows/deploy.yml", []byte(out)); err != nil {
		t.Fatalf("fixed output no longer parses: %v\n%s", err, out)
	}
}

func TestFixCloudStaticCredentialsAnnotatesEnvEntry(t *testing.T) {
	const in = `on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: aws s3 sync ./dist s3://bucket
        env:
          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
`
	out, n := fixOnce(t, in)
	if n != 1 {
		t.Fatalf("applied %d fixes, want 1", n)
	}
	if !strings.Contains(out, "AWS_ACCESS_KEY_ID") {
		t.Errorf("fix removed the env entry instead of annotating it:\n%s", out)
	}
	if !strings.Contains(out, "pipefort") {
		t.Errorf("output carries no pipefort marker comment:\n%s", out)
	}
}

// Running the fixer twice must not stack a second identical comment.
func TestFixCloudStaticCredentialsIsIdempotent(t *testing.T) {
	const in = `on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: aws s3 sync ./dist s3://bucket
        env:
          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
`
	once, _ := fixOnce(t, in)
	twice, n := fixOnce(t, once)
	if n != 0 {
		t.Errorf("second pass applied %d fixes, want 0", n)
	}
	if strings.Count(twice, cloudCredentialFixMarker) != 1 {
		t.Errorf("marker appears %d times after two passes, want 1:\n%s",
			strings.Count(twice, cloudCredentialFixMarker), twice)
	}
}
