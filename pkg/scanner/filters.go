package scanner

// confidenceRank orders confidence for min-filtering. Unknown/empty values
// rank highest so unstamped findings are never accidentally dropped.
func confidenceRank(c Confidence) int {
	switch c {
	case ConfidenceLow:
		return 1
	case ConfidenceMedium:
		return 2
	default:
		return 3
	}
}

// StampConfidence backfills Finding.Confidence from the rule's
// DefaultConfidence for findings that don't carry one. SYSTEM findings (empty
// RuleID) and findings for unknown rules default to HIGH. Mutates in place and
// returns the slice for call-site convenience.
func StampConfidence(findings []Finding) []Finding {
	var byID map[RuleID]RuleSpec
	for i := range findings {
		if findings[i].Confidence != "" {
			continue
		}
		if findings[i].RuleID == "" {
			findings[i].Confidence = ConfidenceHigh
			continue
		}
		if byID == nil {
			byID = RuleByID()
		}
		if spec, ok := byID[findings[i].RuleID]; ok {
			findings[i].Confidence = spec.DefaultConfidence
		} else {
			findings[i].Confidence = ConfidenceHigh
		}
	}
	return findings
}

// FilterByConfidence keeps findings at or above the given minimum confidence.
// An empty minimum (or LOW) keeps everything. SYSTEM findings always pass.
func FilterByConfidence(findings []Finding, min Confidence) []Finding {
	if min == "" || min == ConfidenceLow {
		return findings
	}
	minRank := confidenceRank(min)
	out := make([]Finding, 0, len(findings))
	for _, f := range findings {
		if f.RuleID == "" || confidenceRank(f.Confidence) >= minRank {
			out = append(out, f)
		}
	}
	return out
}

// FilterByPersona keeps findings whose rule belongs to the selected persona
// tier or below: `regular` keeps only regular rules, `pedantic` adds pedantic
// ones, `auditor` keeps everything. SYSTEM findings and unknown rules always
// pass.
func FilterByPersona(findings []Finding, persona Persona) []Finding {
	if persona == PersonaAuditor {
		return findings
	}
	maxRank := personaRank(persona)
	byID := RuleByID()
	out := make([]Finding, 0, len(findings))
	for _, f := range findings {
		if f.RuleID == "" {
			out = append(out, f)
			continue
		}
		spec, ok := byID[f.RuleID]
		if !ok || personaRank(spec.Persona) <= maxRank {
			out = append(out, f)
		}
	}
	return out
}
