package scanner

import (
	"strings"
	"testing"
)

// --- CICD-SEC-2: static cloud credentials where OIDC federation belongs -----

func TestCheckCloudCredentials(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		// wantProviders is the provider label expected in each finding's
		// description, in file order. An empty slice means "no findings".
		wantProviders []string
		wantConf      Confidence
	}{
		{
			name: "aws login action with static access keys triggers",
			yaml: `
on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: us-east-1
`,
			wantProviders: []string{"AWS"},
			wantConf:      ConfidenceHigh,
		},
		{
			name: "aws login action federated with role-to-assume is clean",
			yaml: `
on: push
permissions:
  id-token: write
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/deploy
          aws-region: us-east-1
`,
		},
		{
			name: "gcp auth action with credentials_json triggers",
			yaml: `
on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: google-github-actions/auth@v2
        with:
          credentials_json: ${{ secrets.GCP_SA_KEY }}
`,
			wantProviders: []string{"GCP"},
			wantConf:      ConfidenceHigh,
		},
		{
			name: "gcp auth action with workload identity federation is clean",
			yaml: `
on: push
permissions:
  id-token: write
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: google-github-actions/auth@v2
        with:
          workload_identity_provider: projects/1/locations/global/workloadIdentityPools/p/providers/gh
          service_account: sa@example.iam.gserviceaccount.com
`,
		},
		{
			name: "azure login with a service-principal secret triggers",
			yaml: `
on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: azure/login@v2
        with:
          creds: ${{ secrets.AZURE_CREDENTIALS }}
`,
			wantProviders: []string{"Azure"},
			wantConf:      ConfidenceHigh,
		},
		{
			name: "azure login federated with client-id and tenant-id is clean",
			yaml: `
on: push
permissions:
  id-token: write
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: azure/login@v2
        with:
          client-id: ${{ secrets.AZURE_CLIENT_ID }}
          tenant-id: ${{ secrets.AZURE_TENANT_ID }}
          subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}
`,
		},
		{
			name: "static AWS keys in step env triggers",
			yaml: `
on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: aws s3 sync ./dist s3://bucket
        env:
          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
          AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
`,
			// One finding per static credential key, both AWS.
			wantProviders: []string{"AWS", "AWS"},
			wantConf:      ConfidenceHigh,
		},
		{
			name: "static GCP service-account key in workflow env triggers",
			yaml: `
on: push
env:
  GCP_SA_KEY: ${{ secrets.GCP_SA_KEY }}
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: gcloud storage cp ./dist gs://bucket
`,
			wantProviders: []string{"GCP"},
			wantConf:      ConfidenceHigh,
		},
		{
			name: "literal AKIA access key in env triggers",
			yaml: `
on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: aws s3 ls
        env:
          MY_KEY: AKIAIOSFODNN7EXAMPLE
`,
			wantProviders: []string{"AWS"},
			wantConf:      ConfidenceHigh,
		},
		{
			name: "gcloud auth activate-service-account in run triggers",
			yaml: `
on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: gcloud auth activate-service-account --key-file=key.json
`,
			wantProviders: []string{"GCP"},
			wantConf:      ConfidenceMedium,
		},
		{
			name: "az login with a service principal secret in run triggers",
			yaml: `
on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: az login --service-principal -u $APP_ID -p $CLIENT_SECRET --tenant $TENANT
`,
			wantProviders: []string{"Azure"},
			wantConf:      ConfidenceMedium,
		},
		{
			name: "aws configure set access key in run triggers",
			yaml: `
on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: aws configure set aws_access_key_id "$KEY"
`,
			wantProviders: []string{"AWS"},
			wantConf:      ConfidenceMedium,
		},
		{
			name: "unrelated workflow is clean",
			yaml: `
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: go build ./...
        env:
          CGO_ENABLED: "0"
`,
		},
		{
			name: "AWS_REGION alone is not a credential",
			yaml: `
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: aws s3 ls
        env:
          AWS_REGION: us-east-1
`,
		},
		{
			name: "generic OIDC token request is clean",
			yaml: `
on: push
permissions:
  id-token: write
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: |
          curl -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" "$ACTIONS_ID_TOKEN_REQUEST_URL"
`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wf, jobs := parseTestWorkflow(t, tc.yaml)
			got := CheckCloudCredentials("test.yml", wf, jobs)
			if len(got) != len(tc.wantProviders) {
				t.Fatalf("got %d findings, want %d (findings=%+v)", len(got), len(tc.wantProviders), got)
			}
			for i, f := range got {
				if f.RuleID != RuleCloudStaticCredentials {
					t.Errorf("finding %d: got rule %q, want %q", i, f.RuleID, RuleCloudStaticCredentials)
				}
				if f.Category != "CICD-SEC-2" {
					t.Errorf("finding %d: got category %q, want CICD-SEC-2", i, f.Category)
				}
				if f.Severity != SeverityMedium {
					t.Errorf("finding %d: got severity %q, want MEDIUM", i, f.Severity)
				}
				if !strings.Contains(f.Description, tc.wantProviders[i]) {
					t.Errorf("finding %d: description missing provider %q: %s", i, tc.wantProviders[i], f.Description)
				}
				if f.Confidence != tc.wantConf {
					t.Errorf("finding %d: got confidence %q, want %q", i, f.Confidence, tc.wantConf)
				}
				if f.Line == 0 {
					t.Errorf("finding %d: line is 0, want the offending node's line", i)
				}
				if !strings.Contains(f.Recommendation, "OIDC") {
					t.Errorf("finding %d: recommendation should point at OIDC federation: %s", i, f.Recommendation)
				}
			}
		})
	}
}

// A federated login step in one job must not silence a static login in
// another — the finding names the credential that is still on the shelf.
func TestCheckCloudCredentialsPerJob(t *testing.T) {
	const y = `
on: push
permissions:
  id-token: write
jobs:
  federated:
    runs-on: ubuntu-latest
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/deploy
  legacy:
    runs-on: ubuntu-latest
    steps:
      - uses: google-github-actions/auth@v2
        with:
          credentials_json: ${{ secrets.GCP_SA_KEY }}
`
	wf, jobs := parseTestWorkflow(t, y)
	got := CheckCloudCredentials("test.yml", wf, jobs)
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(got), got)
	}
	if !strings.Contains(got[0].Description, "legacy") {
		t.Errorf("description should name the job holding the credential: %s", got[0].Description)
	}
	if !strings.Contains(got[0].Description, "GCP_SA_KEY") {
		t.Errorf("description should name the secret that OIDC would retire: %s", got[0].Description)
	}
}

// The rule is portable: the same RuleID fires on GitLab CI, driven by
// `variables:` blocks and script lines rather than actions.
func TestGitLabCloudCredentials(t *testing.T) {
	t.Run("static AWS keys in job variables trigger", func(t *testing.T) {
		f := wantRule(t, scanGL(t, `
deploy:
  variables:
    AWS_ACCESS_KEY_ID: $AWS_ACCESS_KEY_ID
    AWS_SECRET_ACCESS_KEY: $AWS_SECRET_ACCESS_KEY
  script:
    - aws s3 sync ./dist s3://bucket
`), RuleCloudStaticCredentials)
		if f.Category != "CICD-SEC-2" {
			t.Errorf("got category %q, want CICD-SEC-2", f.Category)
		}
		if !strings.Contains(f.Description, "AWS") {
			t.Errorf("description missing provider: %s", f.Description)
		}
	})

	t.Run("top-level variables trigger", func(t *testing.T) {
		wantRule(t, scanGL(t, `
variables:
  GCP_SA_KEY: $GCP_SA_KEY

deploy:
  script:
    - gcloud storage cp ./dist gs://bucket
`), RuleCloudStaticCredentials)
	})

	t.Run("gcloud activate-service-account in script triggers", func(t *testing.T) {
		wantRule(t, scanGL(t, `
deploy:
  script:
    - gcloud auth activate-service-account --key-file=key.json
`), RuleCloudStaticCredentials)
	})

	t.Run("assuming a role with a web-identity token is clean", func(t *testing.T) {
		wantNoRule(t, scanGL(t, `
deploy:
  id_tokens:
    GITLAB_OIDC_TOKEN:
      aud: https://gitlab.com
  script:
    - aws sts assume-role-with-web-identity --web-identity-token "$GITLAB_OIDC_TOKEN"
`), RuleCloudStaticCredentials)
	})

	t.Run("unrelated job is clean", func(t *testing.T) {
		wantNoRule(t, scanGL(t, `
build:
  script:
    - go build ./...
`), RuleCloudStaticCredentials)
	})
}
