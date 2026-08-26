# Embedded TUF trust anchors

`tuf-repo.github.com/root.json` is the TUF trust anchor for **GitHub's own
Sigstore instance**, which signs attestations for private repositories (public
repositories use Sigstore's public-good instance instead, whose anchor
sigstore-go embeds itself).

It is byte-for-byte the file the GitHub CLI embeds at
`pkg/cmd/attestation/verification/embed/tuf-repo.github.com/root.json`, which is
the authoritative distribution of that anchor. Refresh it from there.

The anchor is only a starting point: the TUF client walks the root chain
forward from it against `https://tuf-repo.github.com`, so an anchor older than
the current root version is expected and correct. Replacing it is only
necessary if GitHub rotates the root keys in a way that breaks the chain.
