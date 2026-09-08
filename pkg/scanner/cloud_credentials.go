package scanner

import (
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// CICD-SEC-2 / CICD-SEC-6 — a pipeline that authenticates to a cloud provider
// with a long-lived static credential where short-lived OIDC federation would
// do.
//
// This is not the "you leaked a key" rule (that is CICD-SEC-6 hardcoded
// secrets, and it fires on the literal). A credential stored correctly in
// secrets is still a credential: it outlives the job that used it, it is
// readable by every workflow in the repository, and rotating it is a manual
// task somebody has to remember. Every major cloud will instead trade the
// runner's OIDC token for a short-lived one, scoped to the repository and the
// ref — which removes the stored credential rather than protecting it.
//
// Three signals, in descending order of certainty:
//
//  1. A recognised cloud login ACTION configured with static inputs. Decided
//     by oidc.go's classifier, so this rule and the OIDCUsage extraction can
//     never disagree about what counts as federated.
//  2. A closed set of static-credential ENV/variable names, or a literal AWS
//     access-key id in a value.
//  3. A cloud CLI invoked in a script in its static-credential form.
//
// (1) and (2) are name-exact and stamp HIGH confidence. (3) matches a command
// line and stamps MEDIUM: a script can name a command it does not run.

// staticCloudEnvKeys maps an environment-variable name that carries a
// long-lived cloud credential to its provider. Closed on purpose — a
// substring match on "KEY" or "SECRET" would flag every unrelated credential
// in the file, which is CICD-SEC-6's job, not this rule's.
var staticCloudEnvKeys = map[string]CloudProvider{
	"AWS_ACCESS_KEY_ID":     CloudAWS,
	"AWS_SECRET_ACCESS_KEY": CloudAWS,

	"GCP_SA_KEY":              CloudGCP,
	"GCP_SERVICE_ACCOUNT_KEY": CloudGCP,
	"GCP_CREDENTIALS":         CloudGCP,
	"GCLOUD_SERVICE_KEY":      CloudGCP,
	"GOOGLE_CREDENTIALS":      CloudGCP,

	"AZURE_CREDENTIALS":   CloudAzure,
	"AZURE_CLIENT_SECRET": CloudAzure,
	"ARM_CLIENT_SECRET":   CloudAzure,
}

// awsAccessKeyLiteralRe matches an AWS access-key id written out in full.
// AWS_SESSION_TOKEN is deliberately absent from every list here: it is the
// short-lived half of the pair, and flagging it would tell people to migrate
// away from the thing they migrated to.
var awsAccessKeyLiteralRe = regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)

// staticCloudLoginCmds are cloud CLI invocations in their static-credential
// form. Each is anchored on the subcommand that consumes the credential, not
// on the CLI name, so `aws s3 sync` and `gcloud storage cp` — which use
// whatever identity the job already has — stay quiet.
var staticCloudLoginCmds = []struct {
	provider CloudProvider
	what     string
	re       *regexp.Regexp
}{
	{CloudAWS, "aws configure set", regexp.MustCompile(`(?i)\baws\s+configure\s+set\s+aws_(?:access_key_id|secret_access_key)\b`)},
	{CloudAWS, "aws sso login", regexp.MustCompile(`(?i)\baws\s+sso\s+login\b`)},
	{CloudGCP, "gcloud auth activate-service-account", regexp.MustCompile(`(?i)\bgcloud\s+auth\s+activate-service-account\b`)},
	{CloudGCP, "gcloud auth login", regexp.MustCompile(`(?i)\bgcloud\s+auth\s+login\b`)},
	// `az login` alone may be a federated login; only the service-principal
	// password form carries a stored secret.
	{CloudAzure, "az login --service-principal", regexp.MustCompile(`(?i)\baz\s+login\b[^\n]*(--service-principal|--password\b|\s-p\s)`)},
}

// cloudProviderLabel is the human name used in finding text. Kept separate
// from the CloudProvider constants (which are wire values consumed by the
// inventory export) so renaming one does not silently change the other.
func cloudProviderLabel(p CloudProvider) string {
	switch p {
	case CloudAWS:
		return "AWS"
	case CloudGCP:
		return "GCP"
	case CloudAzure:
		return "Azure"
	case CloudVault:
		return "Vault"
	}
	return string(p)
}

// remediation names the way out of a stored credential. The two platforms get
// a different one because the token has a different origin: a `permissions:`
// grant on GitHub, an `id_tokens:` block on GitLab. Passed to the shared
// helpers as a function so a finding can never be built with the wrong one.
type remediation func(CloudProvider) string

// githubOIDCRemediation is the provider-specific way out on GitHub Actions.
func githubOIDCRemediation(p CloudProvider) string {
	switch p {
	case CloudAWS:
		return "Grant the job `permissions: id-token: write` and use `aws-actions/configure-aws-credentials` with `role-to-assume:` (an IAM role trusting GitHub's OIDC provider) instead of an access key. Then delete the stored key."
	case CloudGCP:
		return "Grant the job `permissions: id-token: write` and use `google-github-actions/auth` with `workload_identity_provider:` — Workload Identity Federation exchanges the runner's OIDC token for a short-lived access token — instead of a service-account JSON key. Then delete the stored key."
	case CloudAzure:
		return "Grant the job `permissions: id-token: write` and use `azure/login` with `client-id:` + `tenant-id:` + `subscription-id:` against an app registration holding a federated credential for GitHub's OIDC issuer, instead of a client secret. Then delete the stored secret."
	}
	return "Replace the stored credential with short-lived OIDC federation: grant the job `permissions: id-token: write` and configure the provider's login action to exchange the runner's OIDC token for temporary credentials."
}

// gitlabOIDCRemediation is the same way out on GitLab CI.
func gitlabOIDCRemediation(p CloudProvider) string {
	switch p {
	case CloudAWS:
		return "Declare an `id_tokens:` block on the job and exchange the token with `aws sts assume-role-with-web-identity --web-identity-token \"$GITLAB_OIDC_TOKEN\"` against a role trusting GitLab's OIDC provider, instead of a stored access key. Then delete the stored key."
	case CloudGCP:
		return "Declare an `id_tokens:` block on the job and authenticate with Workload Identity Federation (`gcloud iam workload-identity-pools create-cred-config`), which exchanges GitLab's OIDC token for a short-lived access token, instead of a service-account JSON key. Then delete the stored key."
	case CloudAzure:
		return "Declare an `id_tokens:` block on the job and sign in with `az login --service-principal --federated-token \"$GITLAB_OIDC_TOKEN\"` against an app registration holding a federated credential for GitLab's OIDC issuer, instead of a client secret. Then delete the stored secret."
	}
	return "Replace the stored credential with short-lived OIDC federation: declare an `id_tokens:` block on the job and exchange the token for temporary cloud credentials."
}

func cloudCredentialFinding(file string, line, col int, provider CloudProvider, conf Confidence, rec remediation, description string) Finding {
	return Finding{
		File:           file,
		Line:           line,
		Column:         col,
		Severity:       SeverityMedium,
		Category:       "CICD-SEC-2",
		RuleID:         RuleCloudStaticCredentials,
		Title:          fmt.Sprintf("Static %s credential used where OIDC federation is available", cloudProviderLabel(provider)),
		Description:    description,
		Recommendation: rec(provider),
		Confidence:     conf,
	}
}

// dedupeByPosition collects findings, keeping the first one at any given
// line/column. A step can carry both a static login action and a matching env
// block; the same credential named twice is one problem to fix.
type dedupeByPosition struct {
	seen map[[2]int]bool
	out  []Finding
}

func (d *dedupeByPosition) add(fs ...Finding) {
	if d.seen == nil {
		d.seen = map[[2]int]bool{}
	}
	for _, f := range fs {
		key := [2]int{f.Line, f.Column}
		if d.seen[key] {
			continue
		}
		d.seen[key] = true
		d.out = append(d.out, f)
	}
}

// CheckCloudCredentials flags pipelines authenticating to a cloud provider
// with a long-lived static credential rather than short-lived OIDC federation.
func CheckCloudCredentials(file string, workflow *WorkflowNode, jobs []JobNodeWithID) []Finding {
	var acc dedupeByPosition

	acc.add(scanEnvForStaticCloudCreds(file, &workflow.Env, "The workflow-level env block", githubOIDCRemediation)...)

	// Login actions, decided by the oidc.go classifier. Indexed by line so the
	// per-step walk below can emit them in file order alongside env/run
	// findings from the same job.
	authByLine := map[int]OIDCAuth{}
	for _, a := range oidcAuthsIn(file, workflow) {
		if a.Federated || a.Provider == CloudGeneric {
			continue
		}
		authByLine[a.Line] = a
	}

	for _, jobWrap := range jobs {
		j := jobWrap
		acc.add(scanEnvForStaticCloudCreds(file, &j.Node.Env, fmt.Sprintf("The env block of job %q", j.ID), githubOIDCRemediation)...)

		if j.Node.Steps.Kind != yaml.SequenceNode {
			continue
		}
		var steps []StepNode
		if err := j.Node.Steps.Decode(&steps); err != nil {
			continue
		}
		for _, step := range steps {
			s := step

			if a, ok := authByLine[s.Uses.Line]; ok && s.Uses.Value != "" {
				acc.add(cloudCredentialFinding(file, s.Uses.Line, s.Uses.Column, a.Provider, ConfidenceHigh, githubOIDCRemediation,
					fmt.Sprintf(
						"Step %q in job %q authenticates to %s through %s using a long-lived static credential%s. "+
							"%s issues short-lived credentials to a job holding an OIDC token, so this stored credential can be removed rather than rotated.",
						stepName(&s), j.ID, cloudProviderLabel(a.Provider), a.Action,
						secretsClause(a.Secrets), cloudProviderLabel(a.Provider),
					)))
			}

			acc.add(scanEnvForStaticCloudCreds(file, &s.Env, fmt.Sprintf("The env block of step %q in job %q", stepName(&s), j.ID), githubOIDCRemediation)...)

			if s.Run.Value == "" {
				continue
			}
			for _, cmd := range staticCloudLoginCmds {
				if !cmd.re.MatchString(s.Run.Value) {
					continue
				}
				acc.add(cloudCredentialFinding(file, s.Run.Line, s.Run.Column, cmd.provider, ConfidenceMedium, githubOIDCRemediation,
					fmt.Sprintf(
						"Step %q in job %q runs `%s`, which authenticates to %s with a long-lived static credential. "+
							"%s issues short-lived credentials to a job holding an OIDC token, so this stored credential can be removed rather than rotated.",
						stepName(&s), j.ID, cmd.what, cloudProviderLabel(cmd.provider), cloudProviderLabel(cmd.provider),
					)))
				break
			}
		}
	}
	return acc.out
}

// secretsClause names the stored credentials a login step reads, when the
// action's inputs made them nameable.
func secretsClause(secrets []string) string {
	if len(secrets) == 0 {
		return ""
	}
	return fmt.Sprintf(" read from secrets %s", strings.Join(secrets, ", "))
}

// scanEnvForStaticCloudCreds walks an env: (GitHub) or variables: (GitLab)
// mapping for static cloud credentials. One finding per entry at most: a
// recognised key name wins over a literal in its value, so
// `AWS_ACCESS_KEY_ID: AKIA...` is one problem, not two.
func scanEnvForStaticCloudCreds(file string, envNode *yaml.Node, scope string, rec remediation) []Finding {
	if envNode == nil || envNode.Kind != yaml.MappingNode {
		return nil
	}
	var findings []Finding
	for i := 0; i+1 < len(envNode.Content); i += 2 {
		key := envNode.Content[i]
		val := envNode.Content[i+1]

		if provider, ok := staticCloudEnvKeys[strings.ToUpper(strings.TrimSpace(key.Value))]; ok {
			findings = append(findings, cloudCredentialFinding(file, val.Line, val.Column, provider, ConfidenceHigh, rec,
				fmt.Sprintf(
					"%s sets %s, a long-lived static %s credential. "+
						"%s issues short-lived credentials to a job holding an OIDC token, so this stored credential can be removed rather than rotated.",
					scope, key.Value, cloudProviderLabel(provider), cloudProviderLabel(provider),
				)))
			continue
		}

		if val.Kind == yaml.ScalarNode && awsAccessKeyLiteralRe.MatchString(val.Value) {
			findings = append(findings, cloudCredentialFinding(file, val.Line, val.Column, CloudAWS, ConfidenceHigh, rec,
				fmt.Sprintf(
					"%s sets %s to a literal AWS access-key id. Beyond being committed in cleartext, it is a long-lived static AWS credential. "+
						"AWS issues short-lived credentials to a job holding an OIDC token, so this credential can be removed rather than rotated.",
					scope, key.Value,
				)))
		}
	}
	return findings
}

// checkGitLabCloudCredentials is the portable half of the rule: same RuleID,
// driven by `variables:` blocks and script lines because GitLab CI has no
// marketplace login actions to classify.
func checkGitLabCloudCredentials(file string, jobs []glJob, topVars *yaml.Node) []Finding {
	var acc dedupeByPosition

	acc.add(scanEnvForStaticCloudCreds(file, topVars, "The top-level variables block", gitlabOIDCRemediation)...)

	for _, job := range jobs {
		j := job
		acc.add(scanEnvForStaticCloudCreds(file, j.Vars, fmt.Sprintf("The variables block of job %q", j.ID), gitlabOIDCRemediation)...)

		for _, line := range allScripts(j) {
			for _, cmd := range staticCloudLoginCmds {
				if !cmd.re.MatchString(line.Text) {
					continue
				}
				acc.add(cloudCredentialFinding(file, line.Line, line.Column, cmd.provider, ConfidenceMedium, gitlabOIDCRemediation,
					fmt.Sprintf(
						"Job %q runs `%s`, which authenticates to %s with a long-lived static credential. "+
							"%s issues short-lived credentials to a job holding a GitLab OIDC (`id_tokens:`) token, so this stored credential can be removed rather than rotated.",
						j.ID, cmd.what, cloudProviderLabel(cmd.provider), cloudProviderLabel(cmd.provider),
					)))
				break
			}
		}
	}
	return acc.out
}

// --- Auto-fix (partial) -----------------------------------------------------

// cloudCredentialFixMarker tags a comment this fixer wrote, so a second pass
// recognises its own work and does not stack a duplicate.
const cloudCredentialFixMarker = "pipefort: static cloud credential"

// fixCloudStaticCredentials annotates the offending node with the provider's
// OIDC replacement, in a comment.
//
// Comment-only on purpose. The replacement needs a role ARN, a workload
// identity provider, or a federated app registration — none of which exist in
// the file, and none of which can be guessed. Rewriting the login step with a
// placeholder would produce a workflow that parses and then fails at deploy
// time, which is worse than the credential it replaced. So the fix carries the
// exact change to the line that needs it and leaves the pipeline working.
func fixCloudStaticCredentials(rootNode *yaml.Node, f Finding) bool {
	node := findNodeByPosition(rootNode, f.Line, f.Column)
	if node == nil {
		return false
	}

	// Anchor the comment on the mapping KEY when the finding points at a
	// value (an env entry, `uses:`, `run:`), so it renders above the whole
	// entry rather than wedged between the key and its value.
	target := node
	if parent := findParentMappingNode(rootNode, node); parent != nil {
		for i := 0; i+1 < len(parent.Content); i += 2 {
			if parent.Content[i+1] == node {
				target = parent.Content[i]
				break
			}
		}
	}

	if strings.Contains(target.HeadComment, cloudCredentialFixMarker) {
		return false
	}
	comment := fmt.Sprintf("%s — %s\n%s", cloudCredentialFixMarker, f.Title, f.Recommendation)
	if target.HeadComment != "" {
		comment = target.HeadComment + "\n" + comment
	}
	target.HeadComment = comment
	return true
}
