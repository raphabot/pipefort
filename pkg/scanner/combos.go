package scanner

import "sort"

// Toxic combinations ("Attacker Mind") ---------------------------------------
//
// A single Finding is judged in isolation, but real compromises chain several
// together: a pull_request_target that checks out untrusted code is bad; paired
// with a writable GITHUB_TOKEN it becomes a full repository takeover. A
// ToxicCombo names such a higher-impact attack scenario that exists only when a
// SET of findings co-occur.
//
// Detection is pure correlation over already-produced findings, so it lives in
// the engine and is shared verbatim by the CLI and the web API. Combos key off
// RuleID (not Category) because categories are reused across surfaces — e.g.
// CICD-SEC-4 is both the workflow shell-injection rule and the repo-settings
// read-write GITHUB_TOKEN rule, which are very different ingredients.

// ComboSeverity rates a toxic combination. It is deliberately a separate type
// from Finding.Severity: combos can be CRITICAL (above the per-finding scale)
// and must never leak into shouldFail / countBySeverity / CLI exit codes.
type ComboSeverity string

const (
	ComboCritical ComboSeverity = "CRITICAL"
	ComboHigh     ComboSeverity = "HIGH"
)

// ComboScope describes how a combo instance is keyed: "file" combos require
// their anchor ingredient inside one workflow file and emit once per such file;
// "repo" combos correlate repo-wide and emit at most once per scan.
type ComboScope string

const (
	ScopeFile ComboScope = "file"
	ScopeRepo ComboScope = "repo"
)

// AttackStage is one ordered node in the attack chain drawn for a combo.
type AttackStage struct {
	Order       int    `json:"order"`
	Title       string `json:"title"`
	Description string `json:"description"`
	// RuleID links a stage to the component finding responsible for it. Empty
	// for the synthetic terminal "impact" stage.
	RuleID RuleID `json:"rule_id"`
}

// ComboComponent ties a matched requirement back to the concrete finding
// (file:line) that satisfied it.
type ComboComponent struct {
	RuleID  RuleID  `json:"rule_id"`
	Finding Finding `json:"finding"`
}

// ToxicCombo is one detected toxic combination instance.
type ToxicCombo struct {
	ID             string           `json:"id"`
	Title          string           `json:"title"`
	Severity       ComboSeverity    `json:"severity"`
	Scope          ComboScope       `json:"scope"`
	File           string           `json:"file"` // set for file-scoped instances; "" repo-wide
	Impact         string           `json:"impact"`
	BreakChain     string           `json:"break_chain"`
	BreakChainRule RuleID           `json:"break_chain_rule"`
	Stages         []AttackStage    `json:"stages"`
	Components     []ComboComponent `json:"components"`
}

// ruleRef is one alternative that can satisfy a requirement, with the scope in
// which it must be found.
type ruleRef struct {
	rule  RuleID
	scope ComboScope
}

// requirement is satisfied when ANY of its rule alternatives matches (an
// OR-group). A single-element AnyOf is a mandatory rule.
type requirement struct {
	anyOf []ruleRef
}

// stageTmpl is a template attack-chain node. A stage with rule == "" is
// synthetic and always rendered (e.g. the terminal impact). Otherwise the stage
// is rendered only when that rule actually matched, so OR-group alternatives and
// optional amplifiers appear only when present.
type stageTmpl struct {
	title string
	desc  string
	rule  RuleID
}

// comboDef declares one toxic combination.
type comboDef struct {
	id             string
	title          string
	severity       ComboSeverity
	required       []requirement
	optional       []ruleRef
	impact         string
	breakChain     string
	breakChainRule RuleID
	stages         []stageTmpl
}

// fileRef builds a file-scoped rule alternative; repoRef builds a repo-scoped one.
func fileRef(r RuleID) ruleRef { return ruleRef{rule: r, scope: ScopeFile} }
func repoRef(r RuleID) ruleRef { return ruleRef{rule: r, scope: ScopeRepo} }

// comboCatalog is the canonical, ordered list of toxic combinations. Add new
// entries here; DetectToxicCombinations and the docs read from this set.
func comboCatalog() []comboDef {
	return []comboDef{
		{
			id:       "pwn-request",
			title:    "Pwn Request — untrusted PR code runs with a writable token",
			severity: ComboCritical,
			required: []requirement{
				{anyOf: []ruleRef{fileRef(RulePPECheckout)}},
				{anyOf: []ruleRef{fileRef(RuleMissingPermissions), repoRef(RuleWPermWrite)}},
			},
			optional:       []ruleRef{fileRef(RulePPEShellInjection), fileRef(RuleSecretsInheritPRTarget)},
			impact:         "An attacker opens a pull request from a fork; their code executes in the privileged base context with a read-write GITHUB_TOKEN, letting them push to protected branches, steal every repository secret, and tamper with releases — full repository takeover.",
			breakChain:     "Stop checking out the PR head ref in pull_request_target, or move untrusted handling to a pull_request workflow. This single change defeats the whole chain.",
			breakChainRule: RulePPECheckout,
			stages: []stageTmpl{
				{title: "Untrusted code execution", desc: "A pull_request_target workflow checks out the PR head ref, so attacker-controlled code runs in the privileged base context.", rule: RulePPECheckout},
				{title: "Shell injection foothold", desc: "Untrusted event data is interpolated straight into a shell command, giving code execution even without relying on the checkout.", rule: RulePPEShellInjection},
				{title: "All secrets handed to a reusable workflow", desc: "A job calls a reusable workflow with secrets: inherit, widening which credentials the attacker-influenced run can reach.", rule: RuleSecretsInheritPRTarget},
				{title: "Writable token in scope", desc: "The workflow declares no permissions block, so the job inherits a read-write GITHUB_TOKEN the attacker code can use.", rule: RuleMissingPermissions},
				{title: "Writable token in scope", desc: "The repository hands out a read-write GITHUB_TOKEN by default to the attacker-controlled job.", rule: RuleWPermWrite},
				{title: "Repository takeover", desc: "With write access the attacker pushes to protected branches, exfiltrates secrets, and tampers with releases.", rule: ""},
			},
		},
		{
			id:       "poisoned-exfiltration",
			title:    "Poisoned Exfiltration — injection harvests in-scope secrets",
			severity: ComboCritical,
			required: []requirement{
				{anyOf: []ruleRef{fileRef(RulePPEShellInjection)}},
				{anyOf: []ruleRef{
					fileRef(RuleHardcodedSecrets),
					fileRef(RuleLongLivedPAT),
					fileRef(RuleDebugLoggingEnabled),
					fileRef(RuleSecretInRunOutput),
				}},
			},
			optional:       []ruleRef{fileRef(RuleMissingPermissions)},
			impact:         "Attacker-controlled input is executed in a job that also holds reachable secrets (hardcoded credentials, a long-lived PAT, or debug logging that prints masked values). The injected command reads and exfiltrates them to an external host.",
			breakChain:     "Pass untrusted github.event data through an intermediate env var instead of interpolating it into the shell — the injected payload then cannot run.",
			breakChainRule: RulePPEShellInjection,
			stages: []stageTmpl{
				{title: "Command injection", desc: "Untrusted github.event data is interpolated directly into an inline shell script.", rule: RulePPEShellInjection},
				{title: "Reachable hardcoded secret", desc: "A credential is hardcoded in the same workflow, readable by the injected command.", rule: RuleHardcodedSecrets},
				{title: "Long-lived PAT in scope", desc: "The job authenticates with a long-lived personal access token instead of the ephemeral GITHUB_TOKEN, broadening what stolen creds unlock.", rule: RuleLongLivedPAT},
				{title: "Secrets leaked to logs", desc: "Debug logging is enabled, printing unmasked environment values the injected command can scrape from the run.", rule: RuleDebugLoggingEnabled},
				{title: "Secret printed to logs/output", desc: "A step echoes a secret or writes it to step output, putting the plaintext value within reach of the injected command.", rule: RuleSecretInRunOutput},
				{title: "Broad token amplifies blast radius", desc: "No permissions block is set, so the harvested GITHUB_TOKEN is read-write.", rule: RuleMissingPermissions},
				{title: "Secret exfiltration", desc: "The injected command ships the harvested secrets to an attacker-controlled endpoint.", rule: ""},
			},
		},
		{
			id:       "injected-runner-takeover",
			title:    "Injected Runner Takeover — untrusted input runs as RCE on a self-hosted runner",
			severity: ComboCritical,
			required: []requirement{
				{anyOf: []ruleRef{fileRef(RulePPEShellInjection)}},
				{anyOf: []ruleRef{fileRef(RuleSelfHostedRunners)}},
			},
			optional:       []ruleRef{fileRef(RuleMissingTimeout)},
			impact:         "Untrusted github.event data is interpolated into a shell command that runs on a self-hosted, non-ephemeral runner. An external attacker triggers code execution directly on your own infrastructure — no upstream or third-party compromise required. The injected command reads the runner's environment variables, on-disk secrets, and cached credentials, persists across jobs because the host is reused, and pivots into the internal network.",
			breakChain:     "Pass untrusted github.event data through an intermediate env var instead of interpolating it into the shell, so the injected payload can never run. Ephemeral, isolated runners further contain the blast radius.",
			breakChainRule: RulePPEShellInjection,
			stages: []stageTmpl{
				{title: "Command injection", desc: "Untrusted github.event data is interpolated directly into an inline shell command, giving an external attacker arbitrary code execution in the job.", rule: RulePPEShellInjection},
				{title: "Executed on durable infra", desc: "The job runs on a self-hosted runner that persists between jobs, so the injected code lands on your own non-ephemeral infrastructure instead of a throwaway VM.", rule: RuleSelfHostedRunners},
				{title: "Unbounded runtime", desc: "No timeout is set, so the attacker's code can run for hours — mining, exfiltrating, or pivoting — before anyone notices.", rule: RuleMissingTimeout},
				{title: "Runner takeover and persistence", desc: "The attacker reads the runner's environment and on-disk secrets, establishes persistence on the reused host, and pivots into the internal network from inside your perimeter.", rule: ""},
			},
		},
		{
			id:       "persistent-supply-chain-foothold",
			title:    "Persistent Supply-Chain Foothold — hijacked action on durable infra",
			severity: ComboHigh,
			required: []requirement{
				{anyOf: []ruleRef{repoRef(RuleUnpinnedAction)}},
				{anyOf: []ruleRef{repoRef(RuleSelfHostedRunners)}},
			},
			optional:       []ruleRef{repoRef(RuleMissingTimeout)},
			impact:         "A mutable third-party action tag is silently repointed by an upstream compromise. Because it runs on a self-hosted (non-ephemeral) runner, the malicious code gains a persistent foothold on your infrastructure and can move laterally.",
			breakChain:     "Pin every third-party action to a full commit SHA so an upstream tag move can't deliver new code to your runners.",
			breakChainRule: RuleUnpinnedAction,
			stages: []stageTmpl{
				{title: "Mutable dependency", desc: "A third-party action is referenced by tag/branch, not a commit SHA, so its code can change under you.", rule: RuleUnpinnedAction},
				{title: "Upstream hijack executes on durable infra", desc: "The job runs on a self-hosted runner that persists between jobs, so injected code keeps state and access.", rule: RuleSelfHostedRunners},
				{title: "Unbounded runtime", desc: "No timeout is set, so a malicious job can run for hours (mining, exfiltration, lateral movement) before anyone notices.", rule: RuleMissingTimeout},
				{title: "Persistent infrastructure foothold", desc: "The attacker establishes persistence on the runner and pivots into the internal network.", rule: ""},
			},
		},
		{
			id:       "untrusted-rce-on-infra",
			title:    "Untrusted RCE on Infra — remote script piped to shell on a self-hosted runner",
			severity: ComboHigh,
			required: []requirement{
				{anyOf: []ruleRef{repoRef(RulePipeToShell)}},
				{anyOf: []ruleRef{repoRef(RuleSelfHostedRunners)}},
			},
			optional:       []ruleRef{repoRef(RuleWPermWrite)},
			impact:         "A step pipes a network download straight into a shell, executing whatever the server returns at that moment — on a self-hosted runner. A compromised or spoofed endpoint yields remote code execution on persistent internal infrastructure.",
			breakChain:     "Download to a file, verify a checksum/signature, then execute — never pipe curl/wget directly into a shell.",
			breakChainRule: RulePipeToShell,
			stages: []stageTmpl{
				{title: "Remote code fetched and run", desc: "A step pipes curl/wget output directly into sh/bash, running whatever the server returns.", rule: RulePipeToShell},
				{title: "Executed on durable infra", desc: "The job runs on a self-hosted runner, so the fetched code lands on internal, non-ephemeral infrastructure.", rule: RuleSelfHostedRunners},
				{title: "Writable token amplifies impact", desc: "The repository's default read-write GITHUB_TOKEN is in scope for the compromised job.", rule: RuleWPermWrite},
				{title: "Remote code execution on internal infra", desc: "A spoofed or compromised endpoint executes arbitrary code on your runner.", rule: ""},
			},
		},
		{
			id:       "silent-supply-chain-tampering",
			title:    "Silent Supply-Chain Tampering — unverified artifact, failures hidden",
			severity: ComboHigh,
			required: []requirement{
				{anyOf: []ruleRef{repoRef(RuleDownloadNoChecksum)}},
				{anyOf: []ruleRef{
					repoRef(RuleUnpinnedAction),
					repoRef(RuleContinueOnErrorJob),
				}},
			},
			impact:         "An artifact is downloaded without an integrity check, so a tampered binary is accepted. Mutable dependencies widen the tampering surface, and continue-on-error hides any failure the tampering causes — the compromise ships silently.",
			breakChain:     "Verify a checksum, signature, or attestation for every downloaded artifact before using it.",
			breakChainRule: RuleDownloadNoChecksum,
			stages: []stageTmpl{
				{title: "Unverified artifact", desc: "A binary or archive is fetched with no checksum, signature, or attestation check, so a swapped artifact is trusted.", rule: RuleDownloadNoChecksum},
				{title: "Mutable dependency surface", desc: "Unpinned actions broaden where an upstream change can inject tampered code.", rule: RuleUnpinnedAction},
				{title: "Failures suppressed", desc: "continue-on-error reports the job as a success, so the tampering produces no visible failure.", rule: RuleContinueOnErrorJob},
				{title: "Compromised build ships silently", desc: "A tampered artifact flows downstream with no alert raised.", rule: ""},
			},
		},
		{
			id:       "open-trigger-secret-leak",
			title:    "Open Trigger Secret Leak — externally triggered workflow exposes secrets",
			severity: ComboHigh,
			required: []requirement{
				{anyOf: []ruleRef{repoRef(RuleRepoDispatchUnfilt)}},
				{anyOf: []ruleRef{
					repoRef(RuleDebugLoggingEnabled),
					repoRef(RuleHardcodedSecrets),
					repoRef(RuleSecretInRunOutput),
				}},
			},
			optional:       []ruleRef{repoRef(RuleMissingPermissions)},
			impact:         "Any holder of a repo-scoped token can fire the unfiltered repository_dispatch trigger with attacker-chosen inputs, running a workflow that leaks secrets — either by printing unmasked debug logs or by exposing hardcoded credentials in run output.",
			breakChain:     "Add an explicit types: allowlist to the repository_dispatch trigger so only intended event types run the workflow.",
			breakChainRule: RuleRepoDispatchUnfilt,
			stages: []stageTmpl{
				{title: "Unfiltered external trigger", desc: "repository_dispatch has no types: allowlist, so any token holder can fire it with arbitrary inputs.", rule: RuleRepoDispatchUnfilt},
				{title: "Secrets exposed in logs", desc: "Debug logging is on, printing unmasked environment values into logs the trigger can reach.", rule: RuleDebugLoggingEnabled},
				{title: "Hardcoded secret in run output", desc: "A credential is hardcoded in the workflow and surfaces in the externally-triggered run.", rule: RuleHardcodedSecrets},
				{title: "Secret printed to logs/output", desc: "A step echoes a secret or writes it to step output, exposing it in the externally-triggered run.", rule: RuleSecretInRunOutput},
				{title: "Broad token in scope", desc: "No permissions block is set, so the externally-triggered job holds a read-write token.", rule: RuleMissingPermissions},
				{title: "Secret disclosure to an external party", desc: "An outside actor triggers the workflow and reads the exposed secrets.", rule: ""},
			},
		},
		{
			id:       "untrusted-code-on-self-hosted",
			title:    "Untrusted Code on Self-Hosted Runner — fork PR code lands on durable infra",
			severity: ComboHigh,
			required: []requirement{
				{anyOf: []ruleRef{fileRef(RulePPECheckout), fileRef(RuleWorkflowRunArtifactPoisoning)}},
				{anyOf: []ruleRef{repoRef(RuleSelfHostedRunners)}},
			},
			optional:       []ruleRef{fileRef(RuleMissingPermissions), fileRef(RuleCheckoutPersistCreds), repoRef(RuleWPermWrite)},
			impact:         "A pull_request_target/workflow_run workflow runs untrusted fork content (a head-ref checkout or a poisoned artifact) and the repository uses self-hosted runners. The attacker's code executes on non-ephemeral internal infrastructure, where it can persist between jobs, read other tenants' build artifacts, and pivot into the internal network.",
			breakChain:     "Stop running untrusted fork content under a privileged trigger, or run these workflows only on ephemeral GitHub-hosted runners.",
			breakChainRule: RulePPECheckout,
			stages: []stageTmpl{
				{title: "Untrusted code execution", desc: "A privileged-trigger workflow checks out the PR head ref, so attacker-controlled code runs in the pipeline.", rule: RulePPECheckout},
				{title: "Poisoned artifact consumed", desc: "A workflow_run workflow downloads and trusts an artifact produced by the untrusted triggering run.", rule: RuleWorkflowRunArtifactPoisoning},
				{title: "Executed on durable infra", desc: "The repository runs jobs on a self-hosted runner that persists between jobs, so the fetched code lands on internal, non-ephemeral infrastructure.", rule: RuleSelfHostedRunners},
				{title: "Token left in the workspace", desc: "Checkout persists credentials, so the job token sits in .git/config for the untrusted code to read.", rule: RuleCheckoutPersistCreds},
				{title: "Writable token amplifies impact", desc: "No permissions block is set, so the attacker-controlled job holds a read-write GITHUB_TOKEN.", rule: RuleMissingPermissions},
				{title: "Writable token amplifies impact", desc: "The repository hands out a read-write GITHUB_TOKEN by default to the attacker-controlled job.", rule: RuleWPermWrite},
				{title: "Persistent foothold on internal infra", desc: "The attacker establishes persistence on the runner and pivots into the internal network.", rule: ""},
			},
		},
		{
			id:       "secret-exposure-in-logs",
			title:    "Secret Exposure in Logs — debug logging meets an exposed credential",
			severity: ComboHigh,
			required: []requirement{
				{anyOf: []ruleRef{fileRef(RuleDebugLoggingEnabled)}},
				{anyOf: []ruleRef{fileRef(RuleHardcodedSecrets), fileRef(RuleSecretInRunOutput)}},
			},
			impact:         "Debug logging (ACTIONS_STEP_DEBUG) is enabled in the same workflow that exposes a credential — hardcoded, or echoed/written to step output. The runner prints unmasked environment values to logs that anyone with read access to the run can see, exposing the secret to a far wider audience than intended.",
			breakChain:     "Remove the debug-logging env entry; enable it as a one-off re-run option instead of committing it to the workflow.",
			breakChainRule: RuleDebugLoggingEnabled,
			stages: []stageTmpl{
				{title: "Verbose unmasked logging", desc: "ACTIONS_STEP_DEBUG/ACTIONS_RUNNER_DEBUG is enabled, so the runner prints environment values into logs.", rule: RuleDebugLoggingEnabled},
				{title: "Reachable hardcoded secret", desc: "A credential is hardcoded in the same workflow, so it is among the values surfaced in the verbose logs.", rule: RuleHardcodedSecrets},
				{title: "Secret printed to logs/output", desc: "A step echoes a secret or writes it to step output, putting the plaintext value where the verbose logs capture it.", rule: RuleSecretInRunOutput},
				{title: "Secret disclosed to log readers", desc: "Anyone with read access to the workflow run reads the exposed credential.", rule: ""},
			},
		},
		{
			id:       "unverifiable-release",
			title:    "Unverifiable Release — no provenance, built from mutable actions",
			severity: ComboHigh,
			required: []requirement{
				{anyOf: []ruleRef{repoRef(RuleSLSAProvenance)}},
				{anyOf: []ruleRef{repoRef(RuleUnpinnedAction)}},
			},
			optional:       []ruleRef{repoRef(RuleSLSAVerifyStep)},
			impact:         "A workflow publishes a release-shaped artifact without generating a SLSA provenance attestation, and the build pulls in unpinned third-party actions. A tampered action can inject code into the artifact, and consumers have no provenance to detect it — a compromised build ships unverifiably.",
			breakChain:     "Generate a build provenance attestation for published artifacts so consumers can verify what produced them.",
			breakChainRule: RuleSLSAProvenance,
			stages: []stageTmpl{
				{title: "No build provenance", desc: "A release-shaped artifact is published without a SLSA provenance attestation, so its origin can't be verified.", rule: RuleSLSAProvenance},
				{title: "Mutable dependency surface", desc: "Unpinned third-party actions can be repointed upstream to inject code into the build.", rule: RuleUnpinnedAction},
				{title: "No consumer-side verification", desc: "The workflow also consumes artifacts without verifying their provenance, widening the trust gap.", rule: RuleSLSAVerifyStep},
				{title: "Tampered artifact ships unverifiably", desc: "A compromised build flows downstream with no attestation for consumers to check.", rule: ""},
			},
		},
		{
			id:       "gl-pwn-request",
			title:    "GitLab Pwn Request — untrusted MR code runs with pipeline secrets",
			severity: ComboCritical,
			required: []requirement{
				{anyOf: []ruleRef{fileRef(RuleGitLabMRTarget)}},
				{anyOf: []ruleRef{
					fileRef(RuleGitLabShellInjection),
					fileRef(RuleGitLabHardcodedSecrets),
					fileRef(RuleGitLabDebugTrace),
				}},
			},
			impact:         "A job runs on merge_request_event and checks out the MR source branch, executing untrusted contributor code while pipeline CI/CD variables are in scope — and the same pipeline gives that code a concrete way to harvest them (shell injection, a hardcoded credential, or debug-trace log expansion). The result is full secret compromise from an external merge request.",
			breakChain:     "Don't run jobs that check out and execute MR source code on merge_request_event; gate untrusted handling behind protected branches or manual approval.",
			breakChainRule: RuleGitLabMRTarget,
			stages: []stageTmpl{
				{title: "Untrusted MR code execution", desc: "A job runs on merge_request_event and checks out the MR source branch, so contributor-controlled code executes with pipeline variables in scope.", rule: RuleGitLabMRTarget},
				{title: "Shell injection foothold", desc: "Attacker-controlled $CI_MERGE_REQUEST_* / $CI_COMMIT_* data is interpolated into the shell, giving code execution.", rule: RuleGitLabShellInjection},
				{title: "Reachable hardcoded secret", desc: "A credential is hardcoded in the pipeline variables, readable by the untrusted job.", rule: RuleGitLabHardcodedSecrets},
				{title: "Secrets leaked to logs", desc: "CI_DEBUG_TRACE is enabled, expanding masked CI variables into logs the untrusted job can scrape.", rule: RuleGitLabDebugTrace},
				{title: "Pipeline secret compromise", desc: "The attacker harvests and exfiltrates the in-scope CI/CD variables from a single external merge request.", rule: ""},
			},
		},
		{
			id:       "gl-poisoned-exfiltration",
			title:    "GitLab Poisoned Exfiltration — injection harvests in-scope secrets",
			severity: ComboCritical,
			required: []requirement{
				{anyOf: []ruleRef{fileRef(RuleGitLabShellInjection)}},
				{anyOf: []ruleRef{
					fileRef(RuleGitLabHardcodedSecrets),
					fileRef(RuleGitLabPATSecret),
					fileRef(RuleGitLabDebugTrace),
				}},
			},
			impact:         "Attacker-controlled $CI_MERGE_REQUEST_* / $CI_COMMIT_* data is executed in a job that also holds reachable secrets (a hardcoded credential, a long-lived access token, or debug-trace log expansion). The injected command reads and exfiltrates them to an external host.",
			breakChain:     "Pass untrusted $CI_* metadata through an intermediate variable instead of interpolating it into the shell — the injected payload then cannot run.",
			breakChainRule: RuleGitLabShellInjection,
			stages: []stageTmpl{
				{title: "Command injection", desc: "Attacker-controlled $CI_MERGE_REQUEST_* / $CI_COMMIT_* data is interpolated directly into a script line.", rule: RuleGitLabShellInjection},
				{title: "Reachable hardcoded secret", desc: "A credential is hardcoded in the pipeline variables, readable by the injected command.", rule: RuleGitLabHardcodedSecrets},
				{title: "Long-lived token in scope", desc: "The pipeline authenticates with a long-lived access token instead of the ephemeral $CI_JOB_TOKEN, broadening what stolen creds unlock.", rule: RuleGitLabPATSecret},
				{title: "Secrets leaked to logs", desc: "CI_DEBUG_TRACE is enabled, expanding masked CI variables the injected command can scrape.", rule: RuleGitLabDebugTrace},
				{title: "Secret exfiltration", desc: "The injected command ships the harvested secrets to an attacker-controlled endpoint.", rule: ""},
			},
		},
		{
			id:       "gl-persistent-foothold",
			title:    "GitLab Persistent Foothold — hijacked include on a self-hosted runner",
			severity: ComboHigh,
			required: []requirement{
				{anyOf: []ruleRef{repoRef(RuleGitLabUnpinnedInclude)}},
				{anyOf: []ruleRef{repoRef(RuleGitLabSelfHostedTags)}},
			},
			optional:       []ruleRef{repoRef(RuleGitLabMissingTimeout)},
			impact:         "An unpinned include: pulls pipeline configuration from a remote URL or unpinned project ref. When the upstream is repointed by a compromise, the malicious config runs on a self-hosted (non-ephemeral) GitLab runner, giving the attacker a persistent foothold on your infrastructure.",
			breakChain:     "Pin every include: to an immutable ref (commit SHA) so an upstream change can't deliver new pipeline config to your runners.",
			breakChainRule: RuleGitLabUnpinnedInclude,
			stages: []stageTmpl{
				{title: "Mutable pipeline config", desc: "An include: references a remote URL or an unpinned project ref, so the imported config can change under you.", rule: RuleGitLabUnpinnedInclude},
				{title: "Upstream hijack executes on durable infra", desc: "Jobs run on a self-hosted runner that persists between jobs, so injected config keeps state and access.", rule: RuleGitLabSelfHostedTags},
				{title: "Unbounded runtime", desc: "No timeout is set, so a malicious job can run for a long time before anyone notices.", rule: RuleGitLabMissingTimeout},
				{title: "Persistent infrastructure foothold", desc: "The attacker establishes persistence on the runner and pivots into the internal network.", rule: ""},
			},
		},
	}
}

// DetectToxicCombinations correlates the given findings into toxic combinations.
// Callers must pass findings AFTER rule/ruleset filtering so a disabled rule can
// never form a combo. The result is deterministically ordered (severity, then
// id, then file) and is nil for empty input.
func DetectToxicCombinations(findings []Finding) []ToxicCombo {
	if len(findings) == 0 {
		return nil
	}

	// Stable ordering so "first match" and component lists are deterministic.
	sorted := make([]Finding, len(findings))
	copy(sorted, findings)
	sort.SliceStable(sorted, func(i, j int) bool {
		a, b := sorted[i], sorted[j]
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		if a.Column != b.Column {
			return a.Column < b.Column
		}
		return a.RuleID < b.RuleID
	})

	// Indexes: repo-wide rule -> first finding; file -> rule -> first finding.
	repoIndex := map[RuleID]Finding{}
	fileIndex := map[string]map[RuleID]Finding{}
	files := make([]string, 0)
	seenFile := map[string]bool{}
	for _, f := range sorted {
		if f.RuleID == "" {
			continue
		}
		if _, ok := repoIndex[f.RuleID]; !ok {
			repoIndex[f.RuleID] = f
		}
		byRule, ok := fileIndex[f.File]
		if !ok {
			byRule = map[RuleID]Finding{}
			fileIndex[f.File] = byRule
			if !seenFile[f.File] {
				seenFile[f.File] = true
				files = append(files, f.File)
			}
		}
		if _, ok := byRule[f.RuleID]; !ok {
			byRule[f.RuleID] = f
		}
	}

	var combos []ToxicCombo
	for _, def := range comboCatalog() {
		if def.fileKeyed() {
			for _, fp := range files {
				if c, ok := def.match(fp, fileIndex[fp], repoIndex); ok {
					combos = append(combos, c)
				}
			}
		} else {
			if c, ok := def.match("", nil, repoIndex); ok {
				combos = append(combos, c)
			}
		}
	}

	sort.SliceStable(combos, func(i, j int) bool {
		a, b := combos[i], combos[j]
		if a.Severity != b.Severity {
			return severityRank(a.Severity) > severityRank(b.Severity)
		}
		if a.ID != b.ID {
			return a.ID < b.ID
		}
		return a.File < b.File
	})
	return combos
}

// fileKeyed reports whether any rule alternative is file-scoped, in which case
// the combo is anchored to (and emitted per) a workflow file.
func (d comboDef) fileKeyed() bool {
	for _, req := range d.required {
		for _, ref := range req.anyOf {
			if ref.scope == ScopeFile {
				return true
			}
		}
	}
	return false
}

// match evaluates the def for one anchor file (fileRules/file may be empty for
// repo-keyed combos) and builds a ToxicCombo when every requirement is met.
func (d comboDef) match(file string, fileRules map[RuleID]Finding, repoIndex map[RuleID]Finding) (ToxicCombo, bool) {
	lookup := func(ref ruleRef) (Finding, bool) {
		if ref.scope == ScopeFile {
			f, ok := fileRules[ref.rule]
			return f, ok
		}
		f, ok := repoIndex[ref.rule]
		return f, ok
	}

	matched := map[RuleID]bool{}
	var components []ComboComponent

	for _, req := range d.required {
		var hit *ComboComponent
		for _, ref := range req.anyOf {
			if f, ok := lookup(ref); ok {
				hit = &ComboComponent{RuleID: ref.rule, Finding: f}
				break
			}
		}
		if hit == nil {
			return ToxicCombo{}, false
		}
		matched[hit.RuleID] = true
		components = append(components, *hit)
	}

	for _, ref := range d.optional {
		if f, ok := lookup(ref); ok && !matched[ref.rule] {
			matched[ref.rule] = true
			components = append(components, ComboComponent{RuleID: ref.rule, Finding: f})
		}
	}

	var stages []AttackStage
	order := 0
	for _, st := range d.stages {
		if st.rule != "" && !matched[st.rule] {
			continue
		}
		stages = append(stages, AttackStage{Order: order, Title: st.title, Description: st.desc, RuleID: st.rule})
		order++
	}

	scope := ScopeRepo
	if d.fileKeyed() {
		scope = ScopeFile
	}
	return ToxicCombo{
		ID:             d.id,
		Title:          d.title,
		Severity:       d.severity,
		Scope:          scope,
		File:           file,
		Impact:         d.impact,
		BreakChain:     d.breakChain,
		BreakChainRule: d.breakChainRule,
		Stages:         stages,
		Components:     components,
	}, true
}

func severityRank(s ComboSeverity) int {
	switch s {
	case ComboCritical:
		return 2
	case ComboHigh:
		return 1
	default:
		return 0
	}
}
