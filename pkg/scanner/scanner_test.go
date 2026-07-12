package scanner

import (
	"os"
	"testing"
)

// TestScanBytesMatchesScanFile ensures the in-memory entrypoint used by the web
// API produces identical findings to the disk-based ScanFile for the same input.
func TestScanBytesMatchesScanFile(t *testing.T) {
	const fixture = "../../testdata/vulnerable-workflow.yml"

	content, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatalf("failed to read fixture: %v", err)
	}

	fromFile, err := ScanFile(fixture)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	fromBytes, err := ScanBytes(fixture, content)
	if err != nil {
		t.Fatalf("ScanBytes failed: %v", err)
	}

	if len(fromBytes) == 0 {
		t.Fatalf("expected findings from the vulnerable fixture, got none")
	}

	if len(fromFile) != len(fromBytes) {
		t.Fatalf("finding count mismatch: ScanFile=%d ScanBytes=%d", len(fromFile), len(fromBytes))
	}

	for i := range fromFile {
		if fromFile[i] != fromBytes[i] {
			t.Errorf("finding %d mismatch:\n  ScanFile:  %+v\n  ScanBytes: %+v", i, fromFile[i], fromBytes[i])
		}
	}
}

// TestScanBytesIgnoresNonWorkflow confirms non-workflow YAML yields no findings.
func TestScanBytesIgnoresNonWorkflow(t *testing.T) {
	findings, err := ScanBytes("config.yml", []byte("foo: bar\nbaz: 1\n"))
	if err != nil {
		t.Fatalf("ScanBytes failed: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings for non-workflow YAML, got %d", len(findings))
	}
}
