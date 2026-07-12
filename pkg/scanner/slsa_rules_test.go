package scanner

import "testing"

// CheckSLSAProvenance ---------------------------------------------------------

func TestCheckSLSAProvenance(t *testing.T) {
	publishesNoAttest := `
name: Release
on:
  push:
    tags: ['v*']
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
      - uses: softprops/action-gh-release@9d7c94cfd0a1f3ed45544c887983e9fa900f0564
`
	publishesWithAttest := `
name: Release
on:
  push:
    tags: ['v*']
jobs:
  release:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      attestations: write
      contents: read
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
      - uses: actions/attest-build-provenance@b4f9b6c6f5b8e4f3a2b1c0d9e8f7a6b5c4d3e2f1
        with:
          subject-path: out/myapp
      - uses: softprops/action-gh-release@9d7c94cfd0a1f3ed45544c887983e9fa900f0564
`
	noPublishStep := `
name: CI
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: go test ./...
`

	t.Run("publish without attestation triggers finding", func(t *testing.T) {
		wf, jobs := parseTestWorkflow(t, publishesNoAttest)
		findings := CheckSLSAProvenance("test.yml", wf, jobs)
		if len(findings) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(findings))
		}
		if findings[0].RuleID != RuleSLSAProvenance {
			t.Errorf("expected RuleID %q, got %q", RuleSLSAProvenance, findings[0].RuleID)
		}
	})

	t.Run("publish with attestation does not trigger", func(t *testing.T) {
		wf, jobs := parseTestWorkflow(t, publishesWithAttest)
		findings := CheckSLSAProvenance("test.yml", wf, jobs)
		if len(findings) != 0 {
			t.Errorf("expected 0 findings, got %d", len(findings))
		}
	})

	t.Run("no publish step does not trigger", func(t *testing.T) {
		wf, jobs := parseTestWorkflow(t, noPublishStep)
		findings := CheckSLSAProvenance("test.yml", wf, jobs)
		if len(findings) != 0 {
			t.Errorf("expected 0 findings, got %d", len(findings))
		}
	})
}

// CheckSLSAProvenanceIsolated -------------------------------------------------

func TestCheckSLSAProvenanceIsolated(t *testing.T) {
	inJobAttest := `
name: Release
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
      - uses: actions/attest-build-provenance@b4f9b6c6f5b8e4f3a2b1c0d9e8f7a6b5c4d3e2f1
        with:
          subject-path: out/myapp
`
	reusable := `
name: Release
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    outputs:
      digest: ${{ steps.h.outputs.digest }}
    steps:
      - id: h
        run: echo digest=abc >> $GITHUB_OUTPUT
  provenance:
    needs: build
    permissions:
      id-token: write
      contents: read
      actions: read
    uses: slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v2.0.0
    with:
      base64-subjects: ${{ needs.build.outputs.digest }}
`

	t.Run("in-job attestation flags as L2-not-L3", func(t *testing.T) {
		wf, jobs := parseTestWorkflow(t, inJobAttest)
		findings := CheckSLSAProvenanceIsolated("test.yml", wf, jobs)
		if len(findings) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(findings))
		}
		if findings[0].RuleID != RuleSLSAProvenanceIsolated {
			t.Errorf("expected RuleID %q, got %q", RuleSLSAProvenanceIsolated, findings[0].RuleID)
		}
	})

	t.Run("reusable workflow satisfies L3", func(t *testing.T) {
		wf, jobs := parseTestWorkflow(t, reusable)
		findings := CheckSLSAProvenanceIsolated("test.yml", wf, jobs)
		if len(findings) != 0 {
			t.Errorf("expected 0 findings, got %d", len(findings))
		}
	})
}

// CheckSLSAOIDCTokenScope -----------------------------------------------------

func TestCheckSLSAOIDCTokenScope(t *testing.T) {
	missingScope := `
name: Sign
on: push
jobs:
  sign:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
      - uses: actions/attest-build-provenance@b4f9b6c6f5b8e4f3a2b1c0d9e8f7a6b5c4d3e2f1
        with:
          subject-path: out/myapp
`
	hasScope := `
name: Sign
on: push
jobs:
  sign:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read
    steps:
      - uses: actions/attest-build-provenance@b4f9b6c6f5b8e4f3a2b1c0d9e8f7a6b5c4d3e2f1
`
	workflowGrant := `
name: Sign
on: push
permissions:
  id-token: write
  contents: read
jobs:
  sign:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/attest-build-provenance@b4f9b6c6f5b8e4f3a2b1c0d9e8f7a6b5c4d3e2f1
`

	t.Run("signing step missing id-token scope triggers", func(t *testing.T) {
		wf, jobs := parseTestWorkflow(t, missingScope)
		findings := CheckSLSAOIDCTokenScope("test.yml", wf, jobs)
		if len(findings) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(findings))
		}
		if findings[0].RuleID != RuleSLSAOIDCTokenScope {
			t.Errorf("expected RuleID %q, got %q", RuleSLSAOIDCTokenScope, findings[0].RuleID)
		}
	})

	t.Run("job-level grant satisfies the rule", func(t *testing.T) {
		wf, jobs := parseTestWorkflow(t, hasScope)
		findings := CheckSLSAOIDCTokenScope("test.yml", wf, jobs)
		if len(findings) != 0 {
			t.Errorf("expected 0 findings, got %d", len(findings))
		}
	})

	t.Run("workflow-level grant satisfies the rule", func(t *testing.T) {
		wf, jobs := parseTestWorkflow(t, workflowGrant)
		findings := CheckSLSAOIDCTokenScope("test.yml", wf, jobs)
		if len(findings) != 0 {
			t.Errorf("expected 0 findings, got %d", len(findings))
		}
	})
}

// CheckSLSAPermsOverlyBroad ---------------------------------------------------

func TestCheckSLSAPermsOverlyBroad(t *testing.T) {
	writeAllScalar := `
name: Broad
on: push
permissions: write-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
`
	leastPrivilege := `
name: Tight
on: push
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
`
	jobLevelWriteAll := `
name: JobBroad
on: push
permissions:
  contents: read
jobs:
  publish:
    runs-on: ubuntu-latest
    permissions: write-all
    steps:
      - run: echo hi
`

	t.Run("workflow-level write-all triggers", func(t *testing.T) {
		wf, jobs := parseTestWorkflow(t, writeAllScalar)
		findings := CheckSLSAPermsOverlyBroad("test.yml", wf, jobs)
		if len(findings) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(findings))
		}
		if findings[0].RuleID != RuleSLSAPermsOverlyBroad {
			t.Errorf("expected RuleID %q, got %q", RuleSLSAPermsOverlyBroad, findings[0].RuleID)
		}
	})

	t.Run("least-privilege does not trigger", func(t *testing.T) {
		wf, jobs := parseTestWorkflow(t, leastPrivilege)
		findings := CheckSLSAPermsOverlyBroad("test.yml", wf, jobs)
		if len(findings) != 0 {
			t.Errorf("expected 0 findings, got %d", len(findings))
		}
	})

	t.Run("job-level write-all triggers", func(t *testing.T) {
		wf, jobs := parseTestWorkflow(t, jobLevelWriteAll)
		findings := CheckSLSAPermsOverlyBroad("test.yml", wf, jobs)
		if len(findings) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(findings))
		}
	})
}

// CheckSLSACachePoisoning -----------------------------------------------------

func TestCheckSLSACachePoisoning(t *testing.T) {
	poisoned := `
name: PR Cache
on: pull_request_target
jobs:
  cache:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/cache@b4ffde65f46336ab88eb53be808477a3936bae11
        with:
          path: ~/.cache
          key: ${{ runner.os }}-${{ github.head_ref }}
`
	safe := `
name: PR Cache Safe
on: pull_request_target
jobs:
  cache:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/cache@b4ffde65f46336ab88eb53be808477a3936bae11
        with:
          path: ~/.cache
          key: ${{ runner.os }}-${{ hashFiles('**/go.sum') }}
`
	differentTrigger := `
name: PR Cache wrong trigger
on: pull_request
jobs:
  cache:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/cache@b4ffde65f46336ab88eb53be808477a3936bae11
        with:
          path: ~/.cache
          key: ${{ runner.os }}-${{ github.head_ref }}
`

	t.Run("PR-controlled key in pull_request_target triggers", func(t *testing.T) {
		wf, jobs := parseTestWorkflow(t, poisoned)
		findings := CheckSLSACachePoisoning("test.yml", wf, jobs)
		if len(findings) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(findings))
		}
		if findings[0].RuleID != RuleSLSACachePoisoning {
			t.Errorf("expected RuleID %q, got %q", RuleSLSACachePoisoning, findings[0].RuleID)
		}
	})

	t.Run("safe key does not trigger", func(t *testing.T) {
		wf, jobs := parseTestWorkflow(t, safe)
		findings := CheckSLSACachePoisoning("test.yml", wf, jobs)
		if len(findings) != 0 {
			t.Errorf("expected 0 findings, got %d", len(findings))
		}
	})

	t.Run("plain pull_request trigger is out of scope", func(t *testing.T) {
		wf, jobs := parseTestWorkflow(t, differentTrigger)
		findings := CheckSLSACachePoisoning("test.yml", wf, jobs)
		if len(findings) != 0 {
			t.Errorf("expected 0 findings, got %d", len(findings))
		}
	})
}

// CheckSLSAVerifyStep ---------------------------------------------------------

func TestCheckSLSAVerifyStep(t *testing.T) {
	consumesNoVerify := `
name: Consume
on: push
jobs:
  use:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@b4ffde65f46336ab88eb53be808477a3936bae11
      - run: ./run-the-thing
`
	consumesWithVerify := `
name: ConsumeVerify
on: push
jobs:
  use:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@b4ffde65f46336ab88eb53be808477a3936bae11
      - run: gh attestation verify ./pkg.tar.gz --owner my-org
      - run: ./run-the-thing
`
	doesNotConsume := `
name: NoConsume
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: go test ./...
`

	t.Run("consume without verify triggers INFO", func(t *testing.T) {
		wf, jobs := parseTestWorkflow(t, consumesNoVerify)
		findings := CheckSLSAVerifyStep("test.yml", wf, jobs)
		if len(findings) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(findings))
		}
		if findings[0].Severity != SeverityInfo {
			t.Errorf("expected INFO severity, got %s", findings[0].Severity)
		}
		if findings[0].RuleID != RuleSLSAVerifyStep {
			t.Errorf("expected RuleID %q, got %q", RuleSLSAVerifyStep, findings[0].RuleID)
		}
	})

	t.Run("verify step satisfies the rule", func(t *testing.T) {
		wf, jobs := parseTestWorkflow(t, consumesWithVerify)
		findings := CheckSLSAVerifyStep("test.yml", wf, jobs)
		if len(findings) != 0 {
			t.Errorf("expected 0 findings, got %d", len(findings))
		}
	})

	t.Run("workflow that does not consume artifacts is out of scope", func(t *testing.T) {
		wf, jobs := parseTestWorkflow(t, doesNotConsume)
		findings := CheckSLSAVerifyStep("test.yml", wf, jobs)
		if len(findings) != 0 {
			t.Errorf("expected 0 findings, got %d", len(findings))
		}
	})
}
