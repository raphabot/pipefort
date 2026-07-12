package scanner

import (
	"strings"
	"testing"
)

func TestAssignFingerprintsStableAcrossLineShifts(t *testing.T) {
	mk := func(line int) []Finding {
		return []Finding{{
			File:        ".github/workflows/ci.yml",
			Line:        line,
			Column:      3,
			RuleID:      RulePPEShellInjection,
			Title:       "Poisoned Pipeline Execution (Shell Injection)",
			Description: `Step "build" in job "ci" references untrusted event data.`,
		}}
	}
	a, b := mk(10), mk(42)
	AssignFingerprints(a)
	AssignFingerprints(b)
	if a[0].Fingerprint == "" {
		t.Fatal("fingerprint not assigned")
	}
	if a[0].Fingerprint != b[0].Fingerprint {
		t.Fatalf("fingerprint changed with line shift: %q vs %q", a[0].Fingerprint, b[0].Fingerprint)
	}
}

func TestAssignFingerprintsDiscriminates(t *testing.T) {
	base := Finding{
		File:        ".github/workflows/ci.yml",
		RuleID:      RulePPEShellInjection,
		Title:       "T",
		Description: "D",
	}
	otherRule := base
	otherRule.RuleID = RuleMissingTimeout
	otherFile := base
	otherFile.File = ".github/workflows/release.yml"
	otherDesc := base
	otherDesc.Description = "D2"

	fs := []Finding{base, otherRule, otherFile, otherDesc}
	AssignFingerprints(fs)
	seen := map[string]bool{}
	for _, f := range fs {
		if seen[f.Fingerprint] {
			t.Fatalf("collision: %q", f.Fingerprint)
		}
		seen[f.Fingerprint] = true
	}
}

func TestAssignFingerprintsDuplicateOccurrences(t *testing.T) {
	dup := func(line int) Finding {
		return Finding{
			File:        ".github/workflows/ci.yml",
			Line:        line,
			RuleID:      RuleUnpinnedImage,
			Title:       "Unpinned image",
			Description: "container image ubuntu:latest is not pinned by digest",
		}
	}
	// Deliberately out of line order: the suffix must follow line order, not
	// slice order, so the earliest occurrence keeps the bare hash.
	fs := []Finding{dup(30), dup(10), dup(20)}
	AssignFingerprints(fs)

	if strings.Contains(fs[1].Fingerprint, "#") {
		t.Fatalf("earliest occurrence (line 10) should keep the bare hash, got %q", fs[1].Fingerprint)
	}
	if !strings.HasSuffix(fs[2].Fingerprint, "#1") || !strings.HasSuffix(fs[0].Fingerprint, "#2") {
		t.Fatalf("occurrence suffixes wrong: line20=%q line30=%q", fs[2].Fingerprint, fs[0].Fingerprint)
	}
	// All three share the same base hash.
	base := fs[1].Fingerprint
	for _, f := range []Finding{fs[2], fs[0]} {
		if !strings.HasPrefix(f.Fingerprint, base) {
			t.Fatalf("duplicates should share the base hash: %q vs %q", f.Fingerprint, base)
		}
	}
}

func TestFingerprintFieldLengthPrefixing(t *testing.T) {
	a := Finding{File: "ab", Title: "c"}
	b := Finding{File: "a", Title: "bc"}
	fs := []Finding{a, b}
	AssignFingerprints(fs)
	if fs[0].Fingerprint == fs[1].Fingerprint {
		t.Fatal("field boundary collision: (ab,c) == (a,bc)")
	}
}
