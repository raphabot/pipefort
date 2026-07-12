package scanner

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
)

// AssignFingerprints fills each finding's Fingerprint with a stable identity
// for cross-scan tracking. The hash covers what the finding *is* — rule, file,
// title, and the description (which names the job/step/action involved) — and
// deliberately excludes line/column, so unrelated edits that shift a finding
// down a file don't change its identity.
//
// Two genuinely identical findings in one file (same rule, same description —
// e.g. copy-pasted steps) get a stable "#n" occurrence suffix, assigned in
// line order so the earliest occurrence keeps the bare hash across scans.
func AssignFingerprints(findings []Finding) {
	// Index findings per identity hash, then suffix duplicates in line order.
	byHash := map[string][]int{}
	for i := range findings {
		h := fingerprintHash(&findings[i])
		byHash[h] = append(byHash[h], i)
	}
	for h, idxs := range byHash {
		sort.Slice(idxs, func(a, b int) bool {
			fa, fb := &findings[idxs[a]], &findings[idxs[b]]
			if fa.Line != fb.Line {
				return fa.Line < fb.Line
			}
			return fa.Column < fb.Column
		})
		for n, i := range idxs {
			if n == 0 {
				findings[i].Fingerprint = h
			} else {
				findings[i].Fingerprint = fmt.Sprintf("%s#%d", h, n)
			}
		}
	}
}

func fingerprintHash(f *Finding) string {
	h := sha256.New()
	// Length-prefix each field so ("a","bc") never collides with ("ab","c").
	for _, part := range []string{string(f.RuleID), f.File, f.Title, f.Description} {
		fmt.Fprintf(h, "%d:%s", len(part), part)
	}
	return hex.EncodeToString(h.Sum(nil))
}
