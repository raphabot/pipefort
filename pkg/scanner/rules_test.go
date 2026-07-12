package scanner

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func parseTestWorkflow(t *testing.T, content string) (*WorkflowNode, []JobNodeWithID) {
	t.Helper()
	var workflow WorkflowNode
	if err := yaml.Unmarshal([]byte(content), &workflow); err != nil {
		t.Fatalf("failed to unmarshal yaml for test: %v", err)
	}

	var jobs []JobNodeWithID
	if workflow.Jobs.Kind == yaml.MappingNode {
		for i := 0; i < len(workflow.Jobs.Content); i += 2 {
			keyNode := workflow.Jobs.Content[i]
			valNode := workflow.Jobs.Content[i+1]

			var job JobNode
			if err := valNode.Decode(&job); err != nil {
				t.Fatalf("failed to decode job %s: %v", keyNode.Value, err)
			}
			jobs = append(jobs, JobNodeWithID{
				ID:     keyNode.Value,
				Line:   keyNode.Line,
				Column: keyNode.Column,
				Node:   job,
			})
		}
	}
	return &workflow, jobs
}

func TestCheckPPE(t *testing.T) {
	vulnerableYAML := `
name: Vulnerable PPE
on: pull_request
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Print PR Title
        run: |
          echo "Title: ${{ github.event.pull_request.title }}"
`
	secureYAML := `
name: Secure PPE
on: pull_request
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Print PR Title
        env:
          PR_TITLE: ${{ github.event.pull_request.title }}
        run: |
          echo "Title: $PR_TITLE"
`

	t.Run("Vulnerable workflow should trigger PPE finding", func(t *testing.T) {
		wf, jobs := parseTestWorkflow(t, vulnerableYAML)
		findings := CheckPPE("test.yml", wf, jobs)
		if len(findings) != 1 {
			t.Errorf("expected 1 finding, got %d", len(findings))
		} else {
			if findings[0].Category != "CICD-SEC-4" {
				t.Errorf("expected category CICD-SEC-4, got %s", findings[0].Category)
			}
			if findings[0].Severity != SeverityHigh {
				t.Errorf("expected HIGH severity, got %s", findings[0].Severity)
			}
		}
	})

	t.Run("Secure workflow should not trigger PPE finding", func(t *testing.T) {
		wf, jobs := parseTestWorkflow(t, secureYAML)
		findings := CheckPPE("test.yml", wf, jobs)
		if len(findings) != 0 {
			t.Errorf("expected 0 findings, got %d", len(findings))
		}
	})

	t.Run("github.head_ref in run script triggers PPE finding", func(t *testing.T) {
		wf, jobs := parseTestWorkflow(t, `
name: head_ref injection
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "branch ${{ github.head_ref }}"
`)
		findings := CheckPPE("test.yml", wf, jobs)
		if len(findings) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(findings))
		}
		if findings[0].RuleID != RulePPEShellInjection {
			t.Errorf("expected RulePPEShellInjection, got %s", findings[0].RuleID)
		}
	})

	t.Run("review body in run script triggers PPE finding", func(t *testing.T) {
		wf, jobs := parseTestWorkflow(t, `
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: title="${{ github.event.review.body }}"
`)
		if findings := CheckPPE("test.yml", wf, jobs); len(findings) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(findings))
		}
	})

	t.Run("github-script with: input injection triggers PPE finding", func(t *testing.T) {
		wf, jobs := parseTestWorkflow(t, `
on: issue_comment
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/github-script@v7
        with:
          script: |
            console.log("${{ github.event.issue.title }}")
`)
		findings := CheckPPE("test.yml", wf, jobs)
		if len(findings) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(findings))
		}
		if findings[0].RuleID != RulePPEShellInjection {
			t.Errorf("expected RulePPEShellInjection, got %s", findings[0].RuleID)
		}
	})

	t.Run("safe github contexts do not trigger PPE finding", func(t *testing.T) {
		wf, jobs := parseTestWorkflow(t, `
on: pull_request_target
jobs:
  build:
    runs-on: ${{ matrix.os }}
    steps:
      - run: |
          echo "${{ secrets.FOO }}"
          echo "${{ github.sha }}"
`)
		if findings := CheckPPE("test.yml", wf, jobs); len(findings) != 0 {
			t.Fatalf("expected 0 findings, got %d: %+v", len(findings), findings)
		}
	})
}

func TestCheckPBAC(t *testing.T) {
	vulnerableYAML := `
name: Vulnerable PBAC
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "hello"
`
	secureYAMLTopLevel := `
name: Secure PBAC Top
on: push
permissions: read-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "hello"
`
	secureYAMLJobLevel := `
name: Secure PBAC Job
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - run: echo "hello"
`

	t.Run("Vulnerable workflow missing permissions should trigger finding", func(t *testing.T) {
		wf, jobs := parseTestWorkflow(t, vulnerableYAML)
		findings := CheckPBAC("test.yml", wf, jobs)
		if len(findings) != 1 {
			t.Errorf("expected 1 finding, got %d", len(findings))
		} else if findings[0].Category != "CICD-SEC-5" {
			t.Errorf("expected category CICD-SEC-5, got %s", findings[0].Category)
		}
	})

	t.Run("Secure workflow with top-level permissions should not trigger finding", func(t *testing.T) {
		wf, jobs := parseTestWorkflow(t, secureYAMLTopLevel)
		findings := CheckPBAC("test.yml", wf, jobs)
		if len(findings) != 0 {
			t.Errorf("expected 0 findings, got %d", len(findings))
		}
	})

	t.Run("Secure workflow with job-level permissions should not trigger finding", func(t *testing.T) {
		wf, jobs := parseTestWorkflow(t, secureYAMLJobLevel)
		findings := CheckPBAC("test.yml", wf, jobs)
		if len(findings) != 0 {
			t.Errorf("expected 0 findings, got %d", len(findings))
		}
	})
}

func TestCheckUnpinnedActions(t *testing.T) {
	vulnerableYAML := `
name: Unpinned Actions
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4
      - name: Setup Go
        uses: actions/setup-go@main
`
	secureYAML := `
name: Pinned Actions
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4.1.1
      - name: Local Action
        uses: ./.github/actions/my-action
`

	t.Run("Vulnerable workflow with tags should trigger findings", func(t *testing.T) {
		wf, jobs := parseTestWorkflow(t, vulnerableYAML)
		findings := CheckUnpinnedActions("test.yml", wf, jobs)
		if len(findings) != 2 {
			t.Errorf("expected 2 findings, got %d", len(findings))
		}
	})

	t.Run("Secure workflow with SHA pins or local refs should not trigger findings", func(t *testing.T) {
		wf, jobs := parseTestWorkflow(t, secureYAML)
		findings := CheckUnpinnedActions("test.yml", wf, jobs)
		if len(findings) != 0 {
			t.Errorf("expected 0 findings, got %d", len(findings))
		}
	})
}

func TestCheckUntrustedPullRequestTarget(t *testing.T) {
	vulnerableYAML := `
name: Unsafe PR Target
on: pull_request_target
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout PR head
        uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - name: Run Tests
        run: npm test
`
	secureYAML := `
name: Safe PR Target
on: pull_request_target
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout base
        uses: actions/checkout@v4
`

	t.Run("Vulnerable pull_request_target checking out head sha should trigger finding", func(t *testing.T) {
		wf, jobs := parseTestWorkflow(t, vulnerableYAML)
		findings := CheckUntrustedPullRequestTarget("test.yml", wf, jobs)
		if len(findings) != 1 {
			t.Errorf("expected 1 finding, got %d", len(findings))
		} else if findings[0].Category != "CICD-SEC-1" {
			t.Errorf("expected category CICD-SEC-1, got %s", findings[0].Category)
		}
	})

	t.Run("Secure pull_request_target checking out base should not trigger finding", func(t *testing.T) {
		wf, jobs := parseTestWorkflow(t, secureYAML)
		findings := CheckUntrustedPullRequestTarget("test.yml", wf, jobs)
		if len(findings) != 0 {
			t.Errorf("expected 0 findings, got %d", len(findings))
		}
	})

	t.Run("workflow_run checking out upstream head should trigger finding", func(t *testing.T) {
		wf, jobs := parseTestWorkflow(t, `
on:
  workflow_run:
    workflows: [CI]
    types: [completed]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.workflow_run.head_branch }}
      - run: npm test
`)
		findings := CheckUntrustedPullRequestTarget("test.yml", wf, jobs)
		if len(findings) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(findings))
		}
		if findings[0].RuleID != RulePPECheckout {
			t.Errorf("expected RulePPECheckout, got %s", findings[0].RuleID)
		}
	})

	t.Run("pull_request_target checking out head_ref should trigger finding", func(t *testing.T) {
		wf, jobs := parseTestWorkflow(t, `
on: pull_request_target
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.head_ref }}
`)
		if findings := CheckUntrustedPullRequestTarget("test.yml", wf, jobs); len(findings) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(findings))
		}
	})

	t.Run("plain pull_request is not flagged", func(t *testing.T) {
		wf, jobs := parseTestWorkflow(t, `
on: pull_request
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
`)
		if findings := CheckUntrustedPullRequestTarget("test.yml", wf, jobs); len(findings) != 0 {
			t.Fatalf("expected 0 findings, got %d", len(findings))
		}
	})
}

func TestCheckHardcodedSecrets(t *testing.T) {
	vulnerableYAML := `
name: Hardcoded Secrets
on: push
env:
  SUPER_SECRET_KEY: "my-plaintext-api-key"
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Run Deploy
        env:
          SLACK_WEBHOOK_URL: "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
        run: |
          echo "ghp_123456789012345678901234567890123456"
`
	secureYAML := `
name: Safe Secrets
on: push
env:
  SUPER_SECRET_KEY: ${{ secrets.SUPER_SECRET_KEY }}
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Run Deploy
        env:
          SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK }}
        run: |
          echo "No secrets here!"
`

	t.Run("Vulnerable secrets should trigger findings", func(t *testing.T) {
		wf, jobs := parseTestWorkflow(t, vulnerableYAML)
		findings := CheckHardcodedSecrets("test.yml", wf, jobs)
		// We expect 3 findings: env block key, step env block key, and inline script token
		if len(findings) != 3 {
			t.Errorf("expected 3 findings, got %d", len(findings))
		}
	})

	t.Run("Secure secrets should not trigger findings", func(t *testing.T) {
		wf, jobs := parseTestWorkflow(t, secureYAML)
		findings := CheckHardcodedSecrets("test.yml", wf, jobs)
		if len(findings) != 0 {
			t.Errorf("expected 0 findings, got %d", len(findings))
		}
	})
}

func TestCheckPipeToShell(t *testing.T) {
	vulnerableYAML := `
name: Pipe to Shell
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Run installer
        run: |
          curl -s https://example.com/install.sh | bash
`
	secureYAML := `
name: Safe Installer
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Run installer
        run: |
          echo "Safe build step"
`

	t.Run("Vulnerable pipe to shell should trigger finding", func(t *testing.T) {
		wf, jobs := parseTestWorkflow(t, vulnerableYAML)
		findings := CheckPipeToShell("test.yml", wf, jobs)
		if len(findings) != 1 {
			t.Errorf("expected 1 finding, got %d", len(findings))
		} else if findings[0].Category != "BEST-PRAC-1" {
			t.Errorf("expected category BEST-PRAC-1, got %s", findings[0].Category)
		}
	})

	t.Run("Secure workflow should not trigger pipe to shell finding", func(t *testing.T) {
		wf, jobs := parseTestWorkflow(t, secureYAML)
		findings := CheckPipeToShell("test.yml", wf, jobs)
		if len(findings) != 0 {
			t.Errorf("expected 0 findings, got %d", len(findings))
		}
	})

	t.Run("hardened patterns trigger findings", func(t *testing.T) {
		for _, script := range []string{
			"curl -s https://example.com/i.sh | sudo bash",
			"wget -qO- https://example.com/i.sh | bash -s -- --yes",
			"curl https://example.com/get.py | python3",
			"iwr https://example.com/i.ps1 | iex",
		} {
			wf, jobs := parseTestWorkflow(t, `
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: `+script+`
`)
			if findings := CheckPipeToShell("test.yml", wf, jobs); len(findings) != 1 {
				t.Errorf("script %q: expected 1 finding, got %d", script, len(findings))
			}
		}
	})

	t.Run("false-positive guards do not trigger findings", func(t *testing.T) {
		for _, script := range []string{
			"cat script.sh | bash", // no network fetch
			"echo curl | wc -l",    // curl is not fetching anything piped to a shell
		} {
			wf, jobs := parseTestWorkflow(t, `
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: `+script+`
`)
			if findings := CheckPipeToShell("test.yml", wf, jobs); len(findings) != 0 {
				t.Errorf("script %q: expected 0 findings, got %d", script, len(findings))
			}
		}
	})
}

func TestCheckMissingTimeout(t *testing.T) {
	vulnerableYAML := `
name: No Timeout
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "hello"
`
	secureYAML := `
name: Timeout Configured
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 15
    steps:
      - run: echo "hello"
`

	t.Run("Vulnerable missing timeout should trigger finding", func(t *testing.T) {
		wf, jobs := parseTestWorkflow(t, vulnerableYAML)
		findings := CheckMissingTimeout("test.yml", wf, jobs)
		if len(findings) != 1 {
			t.Errorf("expected 1 finding, got %d", len(findings))
		} else if findings[0].Category != "BEST-PRAC-2" {
			t.Errorf("expected category BEST-PRAC-2, got %s", findings[0].Category)
		}
	})

	t.Run("Secure workflow with timeout should not trigger finding", func(t *testing.T) {
		wf, jobs := parseTestWorkflow(t, secureYAML)
		findings := CheckMissingTimeout("test.yml", wf, jobs)
		if len(findings) != 0 {
			t.Errorf("expected 0 findings, got %d", len(findings))
		}
	})
}

func TestCheckSelfHostedRunners(t *testing.T) {
	vulnerableYAML := `
name: Self Hosted
on: push
jobs:
  build:
    runs-on: self-hosted
    steps:
      - run: echo "hello"
`
	secureYAML := `
name: GitHub Hosted
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "hello"
`

	t.Run("Vulnerable self-hosted runner should trigger finding", func(t *testing.T) {
		wf, jobs := parseTestWorkflow(t, vulnerableYAML)
		findings := CheckSelfHostedRunners("test.yml", wf, jobs)
		if len(findings) != 1 {
			t.Errorf("expected 1 finding, got %d", len(findings))
		} else if findings[0].Category != "BEST-PRAC-3" {
			t.Errorf("expected category BEST-PRAC-3, got %s", findings[0].Category)
		}
	})

	t.Run("Secure workflow with github hosted runner should not trigger finding", func(t *testing.T) {
		wf, jobs := parseTestWorkflow(t, secureYAML)
		findings := CheckSelfHostedRunners("test.yml", wf, jobs)
		if len(findings) != 0 {
			t.Errorf("expected 0 findings, got %d", len(findings))
		}
	})
}

func TestFilterFindings(t *testing.T) {
	findings := []Finding{
		// OWASP only.
		{Category: "CICD-SEC-4", RuleID: RulePPEShellInjection, Title: "Injection"},
		// SLSA Build L1 only.
		{Category: "BEST-PRAC-1", RuleID: RulePipeToShell, Title: "Pipe"},
		// SLSA Build L2 + OWASP.
		{Category: "CICD-SEC-5", RuleID: RuleMissingPermissions, Title: "Perms"},
		// SLSA Build L3 only (new SLSA-only rule).
		{Category: "SLSA-BUILD-L3", RuleID: RuleSLSACachePoisoning, Title: "Cache"},
		// SYSTEM finding (no RuleID).
		{Category: "SYSTEM", Title: "Parse error"},
		// Untagged rule (BEST-PRAC-2 has no frameworks): only appears under 'all'.
		{Category: "BEST-PRAC-2", RuleID: RuleMissingTimeout, Title: "Timeout"},
	}

	t.Run("'all' returns every finding", func(t *testing.T) {
		res := FilterFindings(findings, "all")
		if len(res) != 6 {
			t.Errorf("expected 6 findings, got %d", len(res))
		}
	})

	t.Run("'owasp' keeps OWASP-tagged + SYSTEM", func(t *testing.T) {
		res := FilterFindings(findings, "owasp")
		got := map[string]bool{}
		for _, f := range res {
			got[f.Title] = true
		}
		want := []string{"Injection", "Perms", "Parse error"}
		for _, w := range want {
			if !got[w] {
				t.Errorf("expected %q in result, missing", w)
			}
		}
		if got["Pipe"] || got["Cache"] || got["Timeout"] {
			t.Errorf("owasp leaked non-owasp findings: %v", got)
		}
	})

	t.Run("'slsa' matches any slsa-build-* framework", func(t *testing.T) {
		res := FilterFindings(findings, "slsa")
		got := map[string]bool{}
		for _, f := range res {
			got[f.Title] = true
		}
		want := []string{"Pipe", "Perms", "Cache", "Parse error"}
		for _, w := range want {
			if !got[w] {
				t.Errorf("expected %q in result, missing", w)
			}
		}
		if got["Injection"] || got["Timeout"] {
			t.Errorf("slsa leaked non-slsa findings: %v", got)
		}
	})

	t.Run("'slsa-build-l2' is narrower than 'slsa'", func(t *testing.T) {
		res := FilterFindings(findings, "slsa-build-l2")
		got := map[string]bool{}
		for _, f := range res {
			got[f.Title] = true
		}
		if !got["Perms"] {
			t.Errorf("expected Perms (L2) in result")
		}
		if got["Pipe"] || got["Cache"] {
			t.Errorf("slsa-build-l2 leaked other levels: %v", got)
		}
	})

	t.Run("SYSTEM findings always pass", func(t *testing.T) {
		for _, rs := range []string{"owasp", "slsa", "slsa-build-l3"} {
			res := FilterFindings(findings, rs)
			ok := false
			for _, f := range res {
				if f.Title == "Parse error" {
					ok = true
					break
				}
			}
			if !ok {
				t.Errorf("ruleset %q dropped SYSTEM finding", rs)
			}
		}
	})
}

// TestFrameworkCoverage asserts every rule belongs to at least one framework,
// or is one of the deliberately framework-less "best practice" rules. This
// catches the case where a developer adds a rule and forgets to tag it.
func TestFrameworkCoverage(t *testing.T) {
	// Rules that intentionally have no framework membership. Keep this list
	// short and justified — every other rule must be tagged.
	allowedUntagged := map[RuleID]bool{
		RuleMissingTimeout:        true, // hygiene, not in OWASP/SLSA scope
		RuleGitLabMissingTimeout:  true, // hygiene parallel for GitLab
		RuleGitLabSelfHostedTags:  true, // hygiene parallel for GitLab
		RuleMissingConcurrency:    true, // reliability hygiene, not in OWASP/SLSA scope
		RuleGitLabMissingResGroup: true, // reliability hygiene parallel for GitLab
	}
	for _, r := range Rules() {
		if allowedUntagged[r.ID] {
			continue
		}
		if len(r.Frameworks) == 0 {
			t.Errorf("rule %q has no Frameworks tags — add it to OWASP/SLSA or the allowedUntagged list", r.ID)
		}
	}
}

func TestCheckWorkflowRunArtifactPoisoning(t *testing.T) {
	t.Run("workflow_run downloading artifacts triggers finding", func(t *testing.T) {
		wf, jobs := parseTestWorkflow(t, `
on:
  workflow_run:
    workflows: [CI]
    types: [completed]
jobs:
  comment:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
`)
		got := CheckWorkflowRunArtifactPoisoning("test.yml", wf, jobs)
		if len(got) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(got))
		}
		if got[0].RuleID != RuleWorkflowRunArtifactPoisoning {
			t.Errorf("rule = %q", got[0].RuleID)
		}
	})

	t.Run("gh run download in script triggers finding", func(t *testing.T) {
		wf, jobs := parseTestWorkflow(t, `
on:
  workflow_run:
    types: [completed]
jobs:
  comment:
    runs-on: ubuntu-latest
    steps:
      - run: gh run download ${{ github.event.workflow_run.id }}
`)
		if got := CheckWorkflowRunArtifactPoisoning("test.yml", wf, jobs); len(got) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(got))
		}
	})

	t.Run("download-artifact under push is not flagged", func(t *testing.T) {
		wf, jobs := parseTestWorkflow(t, `
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
`)
		if got := CheckWorkflowRunArtifactPoisoning("test.yml", wf, jobs); len(got) != 0 {
			t.Fatalf("expected 0 findings, got %d", len(got))
		}
	})
}

func TestCheckCheckoutPersistCredentials(t *testing.T) {
	t.Run("checkout without persist-credentials false under pr-target triggers", func(t *testing.T) {
		wf, jobs := parseTestWorkflow(t, `
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
`)
		got := CheckCheckoutPersistCredentials("test.yml", wf, jobs)
		if len(got) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(got))
		}
		if got[0].RuleID != RuleCheckoutPersistCreds {
			t.Errorf("rule = %q", got[0].RuleID)
		}
	})

	t.Run("persist-credentials false is not flagged", func(t *testing.T) {
		wf, jobs := parseTestWorkflow(t, `
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
`)
		if got := CheckCheckoutPersistCredentials("test.yml", wf, jobs); len(got) != 0 {
			t.Fatalf("expected 0 findings, got %d", len(got))
		}
	})

	t.Run("checkout under plain push is not flagged", func(t *testing.T) {
		wf, jobs := parseTestWorkflow(t, `
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
`)
		if got := CheckCheckoutPersistCredentials("test.yml", wf, jobs); len(got) != 0 {
			t.Fatalf("expected 0 findings, got %d", len(got))
		}
	})
}

func TestCheckSecretsInheritPRTarget(t *testing.T) {
	t.Run("secrets inherit on reusable workflow under pr-target triggers", func(t *testing.T) {
		wf, jobs := parseTestWorkflow(t, `
on: pull_request_target
jobs:
  call:
    uses: ./.github/workflows/reusable.yml
    secrets: inherit
`)
		got := CheckSecretsInheritPRTarget("test.yml", wf, jobs)
		if len(got) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(got))
		}
		if got[0].RuleID != RuleSecretsInheritPRTarget {
			t.Errorf("rule = %q", got[0].RuleID)
		}
	})

	t.Run("explicit secrets map is not flagged", func(t *testing.T) {
		wf, jobs := parseTestWorkflow(t, `
on: pull_request_target
jobs:
  call:
    uses: ./.github/workflows/reusable.yml
    secrets:
      token: ${{ secrets.SCOPED }}
`)
		if got := CheckSecretsInheritPRTarget("test.yml", wf, jobs); len(got) != 0 {
			t.Fatalf("expected 0 findings, got %d", len(got))
		}
	})

	t.Run("secrets inherit under plain pull_request is not flagged", func(t *testing.T) {
		wf, jobs := parseTestWorkflow(t, `
on: pull_request
jobs:
  call:
    uses: ./.github/workflows/reusable.yml
    secrets: inherit
`)
		if got := CheckSecretsInheritPRTarget("test.yml", wf, jobs); len(got) != 0 {
			t.Fatalf("expected 0 findings, got %d", len(got))
		}
	})
}
