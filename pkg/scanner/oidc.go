package scanner

import (
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// How a workflow authenticates to a cloud, and whether it still needs a stored
// credential to do it.
//
// The rules can tell you a secret is old and widely readable. They cannot tell
// you the thing that decides what to do about it: whether the workflow reading
// it could stop needing it at all. GitHub will mint a short-lived OIDC token
// for a job that asks for one, and every major cloud login action accepts that
// token in place of a long-lived key — so "rotate this quarterly" and "delete
// this permanently" are different answers to the same stale row.
//
// This is extraction, not detection. It produces no findings. A static
// credential is not a vulnerability and this makes no claim that it is; it
// reports what the file does so a consumer holding an inventory can join the
// two and say which stored credentials have a way out.

// CloudProvider is the cloud a login step authenticates to.
type CloudProvider string

const (
	CloudAWS   CloudProvider = "aws"
	CloudGCP   CloudProvider = "gcp"
	CloudAzure CloudProvider = "azure"
	CloudVault CloudProvider = "vault"
	// CloudGeneric is a job requesting the OIDC token directly — through
	// core.getIDToken() or the ACTIONS_ID_TOKEN_REQUEST_URL endpoint — rather
	// than through a known login action. It is federated by construction:
	// nothing else can produce that token.
	CloudGeneric CloudProvider = "generic"
)

// OIDCAuth is one place a workflow authenticates to a cloud.
//
// Deliberately flat. The three interesting states are combinations of two
// booleans, and giving them a single enum here would fix the vocabulary of
// every consumer to whatever names made sense today.
type OIDCAuth struct {
	File string `json:"file"`
	Job  string `json:"job"`
	Line int    `json:"line"`

	Provider CloudProvider `json:"provider"`
	// Action is the marketplace action that decided this, without its version
	// (e.g. "aws-actions/configure-aws-credentials"). Empty for CloudGeneric.
	Action string `json:"action,omitempty"`

	// TokenGranted is whether the JOB can mint an OIDC token at all:
	// permissions.id-token is write, at job level if the job sets permissions,
	// otherwise at workflow level.
	//
	// Kept separate from Federated because the mismatch is real and silent. A
	// step configured for OIDC in a job with no id-token permission does not
	// fall back to anything — it fails at run time, and it fails the same way
	// whether the role is wrong or the permission is missing.
	TokenGranted bool `json:"token_granted"`
	// Federated is whether THIS step is configured to use that token instead
	// of a stored credential.
	Federated bool `json:"federated"`

	// Secrets are the stored credentials this step reads, when it is not
	// federated — the inventory rows that adopting OIDC here would retire.
	// Sorted, and empty when the credentials come from somewhere else (a
	// variable, a hardcoded value, an env var set elsewhere).
	Secrets []string `json:"secrets,omitempty"`
}

// cloudLogin describes one recognised login action.
//
// Membership is a judgement about evidence, not about popularity: an action
// earns a place only when its own inputs distinguish federated from static
// authentication. An action that logs in through inputs we cannot tell apart
// would produce rows claiming a credential can be retired without knowing
// whether it can.
type cloudLogin struct {
	provider CloudProvider
	// federatedAny are `with:` keys where ONE is enough: each only makes sense
	// with an OIDC token.
	federatedAny []string
	// federatedAll are keys that only mean OIDC together. Azure's client-id
	// appears in the static form too, so half the evidence is no evidence —
	// the distinction between these two lists is what stops a
	// client-id-plus-client-secret login being read as federated.
	federatedAll []string
	// staticInputs are `with:` keys that carry a stored credential. Their
	// presence wins: an action given both an access key and a role assumes the
	// role WITH the key, and no token is involved.
	staticInputs []string
}

var cloudLogins = map[string]cloudLogin{
	"aws-actions/configure-aws-credentials": {
		provider:     CloudAWS,
		federatedAny: []string{"role-to-assume", "web-identity-token-file"},
		staticInputs: []string{"aws-access-key-id", "aws-secret-access-key", "aws-session-token"},
	},
	"google-github-actions/auth": {
		provider:     CloudGCP,
		federatedAny: []string{"workload_identity_provider"},
		staticInputs: []string{"credentials_json"},
	},
	"azure/login": {
		provider:     CloudAzure,
		federatedAll: []string{"client-id", "tenant-id"},
		staticInputs: []string{"creds", "client-secret"},
	},
	"hashicorp/vault-action": {
		provider: CloudVault,
		// method: jwt is checked separately — it is a value, not a key.
		staticInputs: []string{"token", "secretId", "roleId", "password"},
	},
}

// OIDCUsage returns every cloud authentication in one workflow file, in file
// order.
//
// It returns nil for a file it cannot parse or that is not a workflow —
// silence rather than an error, matching ScanBytes and SecretReferences,
// because a caller sweeping a repository should not have one odd file end the
// sweep.
//
// A job with id-token: write and no recognised login step produces NOTHING.
// That is deliberate: the permission alone says the job may mint a token, not
// that it uses one, and emitting a row for it would put "adopted OIDC" beside
// a job that does nothing of the kind.
func OIDCUsage(file string, content []byte) []OIDCAuth {
	var workflow WorkflowNode
	if err := yaml.Unmarshal(content, &workflow); err != nil {
		return nil
	}
	if workflow.Jobs.Kind == 0 && workflow.On.Kind == 0 {
		return nil
	}
	return oidcAuthsIn(file, &workflow)
}

// oidcAuthsIn is OIDCUsage over an already-parsed workflow. The Check*
// functions receive the parsed tree rather than the raw bytes, and re-parsing
// there would let the extraction and the rule drift apart on the same file.
func oidcAuthsIn(file string, workflow *WorkflowNode) []OIDCAuth {
	workflowGrant := idTokenWrite(&workflow.Permissions)

	var out []OIDCAuth
	if workflow.Jobs.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(workflow.Jobs.Content); i += 2 {
		jobID := workflow.Jobs.Content[i].Value
		jobNode := workflow.Jobs.Content[i+1]

		// GitHub's rule, not an approximation of it: a job that sets
		// permissions REPLACES the workflow's block entirely rather than
		// merging with it. Inheriting the workflow grant into such a job would
		// report a token the job cannot actually mint.
		grant := workflowGrant
		if perms := mappingValueByKey(jobNode, "permissions"); perms != nil {
			grant = idTokenWrite(perms)
		}

		out = append(out, cloudAuthInJob(file, jobID, jobNode, grant)...)
	}

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Line != out[j].Line {
			return out[i].Line < out[j].Line
		}
		return out[i].Job < out[j].Job
	})
	return out
}

// idTokenWrite reports whether a permissions block grants id-token: write.
//
// `permissions: write-all` grants it too, and `permissions: read-all` or the
// empty `permissions: {}` do not. Reading only the id-token key would call a
// write-all workflow ungranted, which is the one direction that matters: it
// would tell someone to add a permission they already have.
func idTokenWrite(perms *yaml.Node) bool {
	if perms == nil || perms.Kind == 0 {
		return false
	}
	if perms.Kind == yaml.ScalarNode {
		return perms.Value == "write-all"
	}
	v := mappingValueByKey(perms, "id-token")
	return v != nil && v.Kind == yaml.ScalarNode && v.Value == "write"
}

func cloudAuthInJob(file, job string, jobNode *yaml.Node, grant bool) []OIDCAuth {
	steps := mappingValueByKey(jobNode, "steps")
	if steps == nil || steps.Kind != yaml.SequenceNode {
		return nil
	}
	var out []OIDCAuth
	for _, step := range steps.Content {
		if step.Kind != yaml.MappingNode {
			continue
		}
		if auth := cloudAuthInStep(file, job, step, grant); auth != nil {
			out = append(out, *auth)
		}
	}
	return out
}

func cloudAuthInStep(file, job string, step *yaml.Node, grant bool) *OIDCAuth {
	uses := mappingValueByKey(step, "uses")
	with := mappingValueByKey(step, "with")

	if uses != nil && uses.Kind == yaml.ScalarNode {
		name := actionRepo(uses.Value)
		if login, ok := cloudLogins[name]; ok {
			auth := OIDCAuth{
				File: file, Job: job, Line: uses.Line,
				Provider: login.provider, Action: name, TokenGranted: grant,
			}
			auth.Federated, auth.Secrets = classifyLogin(login, with)
			return &auth
		}
	}

	// Asking GitHub for the token directly. Nothing else can produce it, so
	// this is federated by construction — and it is how a workflow federates
	// against a cloud with no login action of its own.
	if line, ok := rawTokenRequest(step); ok {
		return &OIDCAuth{
			File: file, Job: job, Line: line,
			Provider: CloudGeneric, TokenGranted: grant, Federated: true,
		}
	}
	return nil
}

// classifyLogin decides whether a login step uses the OIDC token, and which
// stored secrets it reads if it does not.
//
// Static wins over federated when both are configured. An action handed an
// access key does not reach for a token it was not asked for, and reporting it
// as federated would mark a live credential retired.
func classifyLogin(login cloudLogin, with *yaml.Node) (bool, []string) {
	// A static input being PRESENT is what makes the step static. Which
	// secrets it names is a separate question, and often unanswerable — the
	// key may come from a variable or a hardcoded value. Conflating the two
	// would let a credential passed as `${{ vars.X }}` read as federated.
	staticInput := false
	var secrets []string
	for _, key := range login.staticInputs {
		v := mappingValueByKey(with, key)
		if v == nil {
			continue
		}
		staticInput = true
		secrets = append(secrets, secretNamesIn(v)...)
	}
	if staticInput {
		return false, dedupeNonEmpty(secrets)
	}

	if login.provider == CloudVault {
		m := mappingValueByKey(with, "method")
		return m != nil && strings.EqualFold(m.Value, "jwt"), nil
	}
	for _, key := range login.federatedAny {
		if mappingValueByKey(with, key) != nil {
			return true, nil
		}
	}
	if len(login.federatedAll) == 0 {
		return false, nil
	}
	for _, key := range login.federatedAll {
		if mappingValueByKey(with, key) == nil {
			return false, nil
		}
	}
	return true, nil
}

// rawTokenRequest finds a step that mints the OIDC token itself, by calling
// core.getIDToken() or hitting the request endpoint the runner exports.
func rawTokenRequest(step *yaml.Node) (int, bool) {
	for _, key := range []string{"run", "with"} {
		v := mappingValueByKey(step, key)
		if v == nil {
			continue
		}
		if line, ok := containsTokenRequest(v); ok {
			return line, true
		}
	}
	return 0, false
}

func containsTokenRequest(n *yaml.Node) (int, bool) {
	if n == nil {
		return 0, false
	}
	if n.Kind == yaml.ScalarNode {
		if strings.Contains(n.Value, "ACTIONS_ID_TOKEN_REQUEST_URL") ||
			strings.Contains(n.Value, "getIDToken(") {
			return n.Line, true
		}
		return 0, false
	}
	for _, child := range n.Content {
		if line, ok := containsTokenRequest(child); ok {
			return line, true
		}
	}
	return 0, false
}

// secretNamesIn returns the secrets a scalar reads, reusing the reference
// extractor so this and SecretReferences can never disagree about what counts
// as reading a secret.
func secretNamesIn(n *yaml.Node) []string {
	if n == nil || n.Kind != yaml.ScalarNode {
		return nil
	}
	return SecretNamesRead(secretRefsInString("", "", n.Value, n.Line))
}

func dedupeNonEmpty(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil
	}
	return out
}

// actionRepo strips the version from an action reference:
// "aws-actions/configure-aws-credentials@v4" -> "aws-actions/configure-aws-credentials".
func actionRepo(uses string) string {
	return strings.SplitN(strings.TrimSpace(uses), "@", 2)[0]
}

// OIDCAdopted reports whether a set of auths shows a workflow already
// federating: at least one step using the token, and no step still holding a
// stored credential.
//
// Both halves matter. A workflow that federates to AWS and keeps a GCP service
// account key has not adopted OIDC; it has adopted OIDC for AWS, and the
// credential still on the shelf is the one worth naming.
func OIDCAdopted(auths []OIDCAuth) bool {
	federated := false
	for _, a := range auths {
		if a.Federated {
			federated = true
			continue
		}
		if a.Provider != CloudGeneric {
			return false
		}
	}
	return federated
}

// OIDCRetirableSecrets returns the stored credentials that a cloud login step
// reads and that OIDC could replace, sorted and deduplicated.
func OIDCRetirableSecrets(auths []OIDCAuth) []string {
	var all []string
	for _, a := range auths {
		if a.Federated {
			continue
		}
		all = append(all, a.Secrets...)
	}
	return dedupeNonEmpty(all)
}
