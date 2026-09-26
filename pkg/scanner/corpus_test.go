package scanner_test

// Golden corpus: the scanner's eval set. Every file in testdata/corpus is
// scanned offline through the public API and a stable projection of its
// findings is compared to <name>.golden.json. See testdata/corpus/README.md.
//
// Regenerate goldens after an intended behavior change with:
//
//	go test ./pkg/scanner/ -run TestCorpus -update
//
// and review the golden diff like code.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/raphabot/pipefort/pkg/scanner"
)

var updateGoldens = flag.Bool("update", false, "rewrite testdata/corpus/*.golden.json from the current scanner output")

const corpusDir = "../../testdata/corpus"

// corpusFinding is the deterministic projection of a Finding that goldens
// record. Free text (Title/Description/Recommendation) and Fingerprint are
// left out on purpose so wording tweaks don't churn the corpus.
type corpusFinding struct {
	RuleID     string `json:"rule_id"`
	Severity   string `json:"severity"`
	Confidence string `json:"confidence,omitempty"`
	Line       int    `json:"line"`
	Column     int    `json:"column"`
}

type corpusGolden struct {
	Case     string          `json:"case"`
	ScanAs   string          `json:"scan_as"`
	Error    string          `json:"error,omitempty"`
	Findings []corpusFinding `json:"findings"`
}

// failTransport makes any HTTP request during the corpus run fail the test:
// the default scan path must stay offline (engineering/adr/0001).
type failTransport struct{ t *testing.T }

func (f failTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	f.t.Errorf("corpus scan made a network request to %s; the default scan path must be offline", r.URL)
	return nil, errors.New("network disabled in corpus test")
}

// scanNameFor maps a corpus file to the path ScanBytes dispatches on.
// ScanBytes routes by path, so GitLab cases (*.gitlab-ci.yml) are scanned as
// .gitlab-ci/<case>.yml and everything else as a GitHub workflow.
func scanNameFor(file string) (caseName, scanAs string) {
	base := filepath.Base(file)
	if strings.HasSuffix(base, ".gitlab-ci.yml") {
		caseName = strings.TrimSuffix(base, ".gitlab-ci.yml")
		return caseName, ".gitlab-ci/" + caseName + ".yml"
	}
	caseName = strings.TrimSuffix(base, filepath.Ext(base))
	return caseName, ".github/workflows/" + caseName + ".yml"
}

// directives reads the `# expect: <rule>` / `# expect-none: <rule>` lines
// from the file's leading comment block.
func directives(content []byte) (expect, expectNone []string) {
	sc := bufio.NewScanner(bytes.NewReader(content))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, "#") {
			break
		}
		body := strings.TrimSpace(strings.TrimPrefix(line, "#"))
		switch {
		case strings.HasPrefix(body, "expect-none:"):
			expectNone = append(expectNone, strings.TrimSpace(strings.TrimPrefix(body, "expect-none:")))
		case strings.HasPrefix(body, "expect:"):
			expect = append(expect, strings.TrimSpace(strings.TrimPrefix(body, "expect:")))
		}
	}
	return expect, expectNone
}

func project(fs []scanner.Finding) []corpusFinding {
	out := make([]corpusFinding, 0, len(fs))
	for _, f := range fs {
		out = append(out, corpusFinding{
			RuleID:     string(f.RuleID),
			Severity:   string(f.Severity),
			Confidence: string(f.Confidence),
			Line:       f.Line,
			Column:     f.Column,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		if a.Column != b.Column {
			return a.Column < b.Column
		}
		if a.RuleID != b.RuleID {
			return a.RuleID < b.RuleID
		}
		if a.Severity != b.Severity {
			return a.Severity < b.Severity
		}
		return a.Confidence < b.Confidence
	})
	return out
}

func TestCorpus(t *testing.T) {
	orig := http.DefaultTransport
	http.DefaultTransport = failTransport{t: t}
	t.Cleanup(func() { http.DefaultTransport = orig })

	files, err := filepath.Glob(filepath.Join(corpusDir, "*.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatalf("no corpus files found in %s", corpusDir)
	}
	sort.Strings(files)

	for _, file := range files {
		caseName, scanAs := scanNameFor(file)
		t.Run(caseName, func(t *testing.T) {
			content, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			findings, scanErr := scanner.ScanBytes(scanAs, content)
			got := corpusGolden{Case: caseName, ScanAs: scanAs, Findings: project(findings)}
			if scanErr != nil {
				got.Error = scanErr.Error()
			}
			gotJSON, err := json.MarshalIndent(got, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			gotJSON = append(gotJSON, '\n')

			goldenPath := filepath.Join(corpusDir, caseName+".golden.json")
			if *updateGoldens {
				if err := os.WriteFile(goldenPath, gotJSON, 0o644); err != nil {
					t.Fatal(err)
				}
			} else {
				want, err := os.ReadFile(goldenPath)
				if err != nil {
					t.Fatalf("missing golden %s (run: go test ./pkg/scanner/ -run TestCorpus -update, then review it): %v", goldenPath, err)
				}
				if !bytes.Equal(want, gotJSON) {
					t.Errorf("findings for %s drifted from %s.\n--- want\n%s\n--- got\n%s\nIf the change is intended, rerun with -update and review the golden diff.", file, goldenPath, want, gotJSON)
				}
			}

			// The directives are the human intent behind the case; they hold
			// independently of the golden so -update can't silently bless a
			// lost detection or a new false positive.
			seen := map[string]bool{}
			for _, f := range findings {
				seen[string(f.RuleID)] = true
			}
			expect, expectNone := directives(content)
			for _, id := range expect {
				if !seen[id] {
					t.Errorf("%s: expected a %s finding, got none", file, id)
				}
			}
			for _, id := range expectNone {
				if seen[id] {
					t.Errorf("%s: expected no %s finding (look-alike guard), got one", file, id)
				}
			}
		})
	}

	// Every golden must have a matching case, so deleting a case also means
	// deleting its golden.
	goldens, _ := filepath.Glob(filepath.Join(corpusDir, "*.golden.json"))
	cases := map[string]bool{}
	for _, f := range files {
		c, _ := scanNameFor(f)
		cases[c] = true
	}
	for _, g := range goldens {
		c := strings.TrimSuffix(filepath.Base(g), ".golden.json")
		if !cases[c] {
			t.Errorf("orphan golden %s has no corpus case", g)
		}
	}
}
