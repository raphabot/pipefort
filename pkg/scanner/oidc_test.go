package scanner

import (
	"testing"
)

func oidcOf(t *testing.T, yaml string) []OIDCAuth {
	t.Helper()
	return OIDCUsage(".github/workflows/deploy.yml", []byte(yaml))
}

func TestOIDCFederatedAWSLoginIsRecognised(t *testing.T) {
	auths := oidcOf(t, `
name: deploy
on: push
permissions:
  id-token: write
  contents: read
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::1234:role/deploy
          aws-region: eu-west-1
`)
	if len(auths) != 1 {
		t.Fatalf("expected one cloud login, got %d: %+v", len(auths), auths)
	}
	a := auths[0]
	if a.Provider != CloudAWS || a.Action != "aws-actions/configure-aws-credentials" {
		t.Errorf("provider/action = %s/%s", a.Provider, a.Action)
	}
	if !a.Federated || !a.TokenGranted {
		t.Errorf("expected a federated step in a granted job, got %+v", a)
	}
	if len(a.Secrets) != 0 {
		t.Errorf("a federated step retires nothing, got %v", a.Secrets)
	}
}

func TestOIDCStaticAWSLoginNamesTheSecretsItReads(t *testing.T) {
	auths := oidcOf(t, `
on: push
jobs:
  deploy:
    steps:
      - uses: aws-actions/configure-aws-credentials@v2
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: eu-west-1
`)
	if len(auths) != 1 {
		t.Fatalf("expected one cloud login, got %d", len(auths))
	}
	a := auths[0]
	if a.Federated {
		t.Error("a step given an access key is not federated")
	}
	if a.TokenGranted {
		t.Error("no permissions block grants id-token")
	}
	want := []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"}
	if len(a.Secrets) != 2 || a.Secrets[0] != want[0] || a.Secrets[1] != want[1] {
		t.Errorf("secrets = %v, want %v", a.Secrets, want)
	}
}

// The trap this exists for. An action handed BOTH an access key and a role
// assumes the role using that key — no token is involved — and calling it
// federated would mark a live credential retired.
func TestOIDCStaticWinsWhenBothAreConfigured(t *testing.T) {
	auths := oidcOf(t, `
on: push
permissions:
  id-token: write
jobs:
  deploy:
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          role-to-assume: arn:aws:iam::1234:role/deploy
`)
	if len(auths) != 1 {
		t.Fatalf("expected one login, got %d", len(auths))
	}
	if auths[0].Federated {
		t.Fatal("an access key plus a role is still an access key")
	}
	if len(auths[0].Secrets) != 2 {
		t.Errorf("both keys should be named for retirement, got %v", auths[0].Secrets)
	}
}

// A credential that is not a secret reference still makes the step static.
// Reading it as federated because no `secrets.` appeared would be the worst
// possible failure: silence about a live key.
func TestOIDCStaticWithoutASecretReferenceIsStillStatic(t *testing.T) {
	auths := oidcOf(t, `
on: push
jobs:
  deploy:
    steps:
      - uses: google-github-actions/auth@v2
        with:
          credentials_json: ${{ vars.GCP_SA_JSON }}
`)
	if len(auths) != 1 || auths[0].Federated {
		t.Fatalf("expected a static GCP login, got %+v", auths)
	}
	if len(auths[0].Secrets) != 0 {
		t.Errorf("nothing in the inventory can be named here, got %v", auths[0].Secrets)
	}
}

// Job permissions REPLACE the workflow's block rather than merging with it.
// Inheriting the workflow grant here would report a token the job cannot mint.
func TestOIDCJobPermissionsReplaceTheWorkflowBlock(t *testing.T) {
	auths := oidcOf(t, `
on: push
permissions:
  id-token: write
jobs:
  deploy:
    permissions:
      contents: read
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::1234:role/deploy
`)
	if len(auths) != 1 {
		t.Fatalf("expected one login, got %d", len(auths))
	}
	a := auths[0]
	if !a.Federated {
		t.Error("the step is configured for OIDC")
	}
	// …and it will fail at run time, which is exactly the row worth surfacing.
	if a.TokenGranted {
		t.Error("a job that sets its own permissions does not inherit id-token: write")
	}
}

func TestOIDCWriteAllGrantsTheToken(t *testing.T) {
	auths := oidcOf(t, `
on: push
permissions: write-all
jobs:
  deploy:
    steps:
      - uses: azure/login@v2
        with:
          client-id: ${{ vars.AZURE_CLIENT_ID }}
          tenant-id: ${{ vars.AZURE_TENANT_ID }}
`)
	if len(auths) != 1 {
		t.Fatalf("expected one login, got %d", len(auths))
	}
	if !auths[0].TokenGranted {
		t.Error("write-all includes id-token: write — telling someone to add it would be wrong")
	}
	if !auths[0].Federated {
		t.Error("client-id + tenant-id without creds is the federated Azure form")
	}
}

// client-id appears in the static Azure form too, so one half is not evidence.
func TestOIDCAzureNeedsBothHalvesToCountAsFederated(t *testing.T) {
	auths := oidcOf(t, `
on: push
permissions:
  id-token: write
jobs:
  deploy:
    steps:
      - uses: azure/login@v2
        with:
          client-id: ${{ vars.AZURE_CLIENT_ID }}
`)
	if len(auths) != 1 || auths[0].Federated {
		t.Fatalf("client-id alone is not enough to call this federated: %+v", auths)
	}
}

func TestOIDCVaultJWTMethodIsFederated(t *testing.T) {
	auths := oidcOf(t, `
on: push
permissions:
  id-token: write
jobs:
  read:
    steps:
      - uses: hashicorp/vault-action@v3
        with:
          method: jwt
          role: ci
`)
	if len(auths) != 1 || !auths[0].Federated || auths[0].Provider != CloudVault {
		t.Fatalf("expected a federated vault login, got %+v", auths)
	}
}

func TestOIDCVaultTokenIsStatic(t *testing.T) {
	auths := oidcOf(t, `
on: push
jobs:
  read:
    steps:
      - uses: hashicorp/vault-action@v3
        with:
          token: ${{ secrets.VAULT_TOKEN }}
`)
	if len(auths) != 1 || auths[0].Federated {
		t.Fatalf("expected a static vault login, got %+v", auths)
	}
	if len(auths[0].Secrets) != 1 || auths[0].Secrets[0] != "VAULT_TOKEN" {
		t.Errorf("secrets = %v, want [VAULT_TOKEN]", auths[0].Secrets)
	}
}

// A workflow can federate against a cloud with no login action of its own.
func TestOIDCRawTokenRequestCountsAsFederated(t *testing.T) {
	auths := oidcOf(t, `
on: push
permissions:
  id-token: write
jobs:
  deploy:
    steps:
      - run: |
          curl -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
            "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=api://custom"
`)
	if len(auths) != 1 {
		t.Fatalf("expected one generic OIDC use, got %d: %+v", len(auths), auths)
	}
	if auths[0].Provider != CloudGeneric || !auths[0].Federated {
		t.Errorf("asking GitHub for the token is federated by construction, got %+v", auths[0])
	}
}

// The permission on its own says a job MAY mint a token, not that it does.
// Emitting a row here would put "adopted OIDC" beside a job that does nothing
// of the kind.
func TestOIDCGrantWithoutALoginStepReportsNothing(t *testing.T) {
	auths := oidcOf(t, `
on: push
permissions:
  id-token: write
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
      - run: make build
`)
	if len(auths) != 0 {
		t.Fatalf("a permission is not a login, got %+v", auths)
	}
}

func TestOIDCIgnoresNonWorkflowAndBrokenFiles(t *testing.T) {
	if got := OIDCUsage("Dockerfile", []byte("FROM alpine\n")); got != nil {
		t.Errorf("a non-workflow file yields nothing, got %+v", got)
	}
	if got := OIDCUsage("x.yml", []byte("on: push\njobs:\n  a: [oops\n")); got != nil {
		t.Errorf("an unparseable file yields nothing, got %+v", got)
	}
}

// Adoption is per workflow, and a workflow that federates to one cloud while
// keeping another cloud's key has not adopted OIDC.
func TestOIDCAdoptedRequiresEveryLoginToBeFederated(t *testing.T) {
	auths := oidcOf(t, `
on: push
permissions:
  id-token: write
jobs:
  deploy:
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::1234:role/deploy
      - uses: google-github-actions/auth@v2
        with:
          credentials_json: ${{ secrets.GCP_SA_KEY }}
`)
	if len(auths) != 2 {
		t.Fatalf("expected two logins, got %d", len(auths))
	}
	if OIDCAdopted(auths) {
		t.Error("one federated login does not retire the other cloud's key")
	}
	retirable := OIDCRetirableSecrets(auths)
	if len(retirable) != 1 || retirable[0] != "GCP_SA_KEY" {
		t.Errorf("retirable = %v, want [GCP_SA_KEY]", retirable)
	}
}

func TestOIDCAdoptedWhenEveryLoginIsFederated(t *testing.T) {
	auths := oidcOf(t, `
on: push
permissions:
  id-token: write
jobs:
  deploy:
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::1234:role/deploy
`)
	if !OIDCAdopted(auths) {
		t.Error("a workflow whose only login is federated has adopted OIDC")
	}
	if len(OIDCRetirableSecrets(auths)) != 0 {
		t.Error("nothing left to retire")
	}
}

// A file with no cloud auth at all is not "adopted" — there is nothing to
// adopt, and saying yes would count every unrelated workflow as a success.
func TestOIDCAdoptedIsFalseWithNoLogins(t *testing.T) {
	if OIDCAdopted(nil) {
		t.Error("no logins is not adoption")
	}
}
