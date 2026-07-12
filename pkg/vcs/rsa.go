package vcs

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

// rsaKey wraps a parsed RSA private key used to sign GitHub App JWTs.
type rsaKey struct {
	key *rsa.PrivateKey
}

// parseRSAKey accepts a GitHub App private key in either PKCS#1 ("RSA PRIVATE
// KEY") or PKCS#8 ("PRIVATE KEY") PEM form.
func parseRSAKey(pemStr string) (*rsaKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("no PEM block found in private key")
	}

	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return &rsaKey{key: key}, nil
	}

	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaPriv, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not RSA")
	}
	return &rsaKey{key: rsaPriv}, nil
}
