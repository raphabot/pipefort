package scanner

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// CheckUnpinnedImages checks for Dependency Chain Abuse (CICD-SEC-3) via
// container images referenced by a mutable tag instead of an immutable digest.
// Three surfaces are covered, all of which pull an OCI image at run time:
//
//   - job-level `container:` (scalar `image:tag` or a mapping with `image:`)
//   - `services.<name>.image`
//   - step `uses: docker://image:tag`
//
// A tag like `:latest` or `:18` is mutable — the registry can repoint it to a
// different (possibly malicious) image — so the build is only reproducible when
// the image is pinned by `@sha256:` digest. Pure-expression images
// (`${{ ... }}`) are skipped: their value isn't knowable statically.
func CheckUnpinnedImages(file string, workflow *WorkflowNode, jobs []JobNodeWithID) []Finding {
	var findings []Finding

	raw := jobsRawForReusable(workflow)
	for _, jobWrap := range jobs {
		node := raw[jobWrap.ID]
		if node == nil || node.Kind != yaml.MappingNode {
			continue
		}

		// job-level container:
		if c := jobMappingValue(node, "container"); c != nil {
			if img := containerImageNode(c); img != nil && !imagePinnedByDigest(img.Value) {
				findings = append(findings, unpinnedImageFinding(file, img,
					fmt.Sprintf("Job %q runs in container image %q pinned by a mutable tag instead of an immutable digest.", jobWrap.ID, img.Value)))
			}
		}

		// services.<name>.image
		if svcs := jobMappingValue(node, "services"); svcs != nil && svcs.Kind == yaml.MappingNode {
			for i := 0; i+1 < len(svcs.Content); i += 2 {
				svcName := svcs.Content[i].Value
				svcNode := svcs.Content[i+1]
				img := containerImageNode(svcNode)
				if img != nil && !imagePinnedByDigest(img.Value) {
					findings = append(findings, unpinnedImageFinding(file, img,
						fmt.Sprintf("Service %q in job %q uses container image %q pinned by a mutable tag instead of an immutable digest.", svcName, jobWrap.ID, img.Value)))
				}
			}
		}

		// step uses: docker://image:tag
		if jobWrap.Node.Steps.Kind != yaml.SequenceNode {
			continue
		}
		var steps []StepNode
		if err := jobWrap.Node.Steps.Decode(&steps); err != nil {
			continue
		}
		for _, step := range steps {
			s := step
			ref := s.Uses.Value
			if !strings.HasPrefix(ref, "docker://") {
				continue
			}
			image := strings.TrimPrefix(ref, "docker://")
			if strings.Contains(image, "${{") || imagePinnedByDigest(image) {
				continue
			}
			findings = append(findings, unpinnedImageFinding(file, &s.Uses,
				fmt.Sprintf("Step %q in job %q runs container image %q (docker://) pinned by a mutable tag instead of an immutable digest.", stepName(&s), jobWrap.ID, image)))
		}
	}

	return findings
}

// containerImageNode returns the scalar node carrying the image reference for a
// `container:`/service value, which may be either a bare scalar (`image:tag`)
// or a mapping with an `image:` key. Returns nil for expression-only or empty
// values that can't be evaluated statically.
func containerImageNode(node *yaml.Node) *yaml.Node {
	if node == nil {
		return nil
	}
	var img *yaml.Node
	switch node.Kind {
	case yaml.ScalarNode:
		img = node
	case yaml.MappingNode:
		img = jobMappingValue(node, "image")
	}
	if img == nil || img.Kind != yaml.ScalarNode || img.Value == "" {
		return nil
	}
	if strings.Contains(img.Value, "${{") {
		return nil
	}
	return img
}

// imagePinnedByDigest reports whether an image reference is pinned by an
// immutable `@sha256:` digest (optionally in addition to a tag).
func imagePinnedByDigest(ref string) bool {
	return strings.Contains(ref, "@sha256:")
}

func unpinnedImageFinding(file string, at *yaml.Node, description string) Finding {
	return Finding{
		File:           file,
		Line:           at.Line,
		Column:         at.Column,
		Severity:       SeverityMedium,
		Category:       "CICD-SEC-3",
		RuleID:         RuleUnpinnedImage,
		Title:          "Unpinned container image",
		Description:    description + " The registry can repoint the tag to a different image, so the build is neither reproducible nor tamper-evident.",
		Recommendation: "Pin the image by digest (e.g. image@sha256:<digest>). Keep the tag as a comment for readability, and update the digest via Dependabot or Renovate.",
	}
}
