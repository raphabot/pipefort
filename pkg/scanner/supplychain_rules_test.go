package scanner

import "testing"

func TestCheckUnpinnedImages(t *testing.T) {
	cases := []struct {
		name      string
		yaml      string
		wantCount int
	}{
		{
			name: "container scalar pinned by tag is flagged",
			yaml: `
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    container: node:18
    steps:
      - run: echo hi
`,
			wantCount: 1,
		},
		{
			name: "container mapping image pinned by tag is flagged",
			yaml: `
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    container:
      image: node:18
    steps:
      - run: echo hi
`,
			wantCount: 1,
		},
		{
			name: "container pinned by digest is clean",
			yaml: `
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    container: node@sha256:abc123
    steps:
      - run: echo hi
`,
			wantCount: 0,
		},
		{
			name: "services and docker:// step both flagged",
			yaml: `
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    services:
      db:
        image: postgres:16
    steps:
      - uses: docker://alpine:3.18
`,
			wantCount: 2,
		},
		{
			name: "docker:// pinned by digest is clean",
			yaml: `
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: docker://alpine@sha256:deadbeef
`,
			wantCount: 0,
		},
		{
			name: "expression-only image is skipped",
			yaml: `
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    container: ${{ env.IMAGE }}
    steps:
      - run: echo hi
`,
			wantCount: 0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			workflow, jobs := parseTestWorkflow(t, tc.yaml)
			findings := CheckUnpinnedImages("ci.yml", workflow, jobs)
			if len(findings) != tc.wantCount {
				t.Fatalf("got %d findings, want %d: %+v", len(findings), tc.wantCount, findings)
			}
			for _, f := range findings {
				if f.RuleID != RuleUnpinnedImage {
					t.Errorf("unexpected RuleID %q", f.RuleID)
				}
				if f.Line == 0 {
					t.Errorf("finding has no line: %+v", f)
				}
			}
		})
	}
}
