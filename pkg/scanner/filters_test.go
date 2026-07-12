package scanner

import "testing"

func TestStampConfidence(t *testing.T) {
	findings := []Finding{
		{RuleID: RulePPECheckout},                                 // catalog default HIGH
		{RuleID: RuleTyposquatAction},                             // catalog default MEDIUM
		{RuleID: RuleHardcodedSecrets, Confidence: ConfidenceLow}, // pre-stamped stays
		{Category: "SYSTEM"},                                      // empty RuleID → HIGH
		{RuleID: "no-such-rule"},                                  // unknown → HIGH
	}
	StampConfidence(findings)

	want := []Confidence{ConfidenceHigh, ConfidenceMedium, ConfidenceLow, ConfidenceHigh, ConfidenceHigh}
	for i, w := range want {
		if findings[i].Confidence != w {
			t.Errorf("findings[%d].Confidence = %q, want %q", i, findings[i].Confidence, w)
		}
	}
}

func TestFilterByConfidence(t *testing.T) {
	findings := []Finding{
		{RuleID: RulePPECheckout, Confidence: ConfidenceHigh},
		{RuleID: RuleTyposquatAction, Confidence: ConfidenceMedium},
		{RuleID: RuleHardcodedSecrets, Confidence: ConfidenceLow},
		{Category: "SYSTEM"}, // always passes
	}

	for _, tc := range []struct {
		name string
		min  Confidence
		want int
	}{
		{"empty keeps everything", "", 4},
		{"LOW keeps everything", ConfidenceLow, 4},
		{"MEDIUM drops low", ConfidenceMedium, 3},
		{"HIGH keeps high + system", ConfidenceHigh, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := FilterByConfidence(findings, tc.min); len(got) != tc.want {
				t.Errorf("got %d findings, want %d (%v)", len(got), tc.want, got)
			}
		})
	}
}

func TestFilterByPersona(t *testing.T) {
	findings := []Finding{
		{RuleID: RulePPECheckout},       // regular
		{RuleID: RuleMissingTimeout},    // pedantic
		{RuleID: RuleSelfHostedRunners}, // auditor
		{Category: "SYSTEM"},            // always passes
		{RuleID: "no-such-rule"},        // unknown rules pass
	}

	for _, tc := range []struct {
		name    string
		persona Persona
		want    int
	}{
		{"regular keeps high-signal only", PersonaRegular, 3},
		{"pedantic adds hygiene nits", PersonaPedantic, 4},
		{"auditor keeps everything", PersonaAuditor, 5},
		{"unknown persona ranks as regular", Persona("bogus"), 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := FilterByPersona(findings, tc.persona); len(got) != tc.want {
				t.Errorf("got %d findings, want %d (%v)", len(got), tc.want, got)
			}
		})
	}
}

// TestScanBytesStampsConfidence proves every finding leaving the shared scan
// entrypoint carries a confidence — the CLI, web scanner, and future PR checks
// all rely on this.
func TestScanBytesStampsConfidence(t *testing.T) {
	const wf = `
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: echo hi
`
	findings, err := ScanBytes(".github/workflows/ci.yml", []byte(wf))
	if err != nil {
		t.Fatalf("ScanBytes: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings (unpinned action, missing permissions, ...)")
	}
	for _, f := range findings {
		if f.Confidence == "" {
			t.Errorf("finding %s has no confidence stamped", f.RuleID)
		}
	}
}
