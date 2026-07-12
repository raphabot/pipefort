package vcs

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func TestParseRSAKeyPKCS1(t *testing.T) {
	_, pemStr := generateTestKey(t)
	if _, err := parseRSAKey(pemStr); err != nil {
		t.Fatalf("expected PKCS1 key to parse, got %v", err)
	}
}

func TestParseRSAKeyPKCS8(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	if _, err := parseRSAKey(pemStr); err != nil {
		t.Fatalf("expected PKCS8 key to parse, got %v", err)
	}
}

func TestParseRSAKeyRejectsGarbage(t *testing.T) {
	if _, err := parseRSAKey("not a pem"); err == nil {
		t.Fatal("expected error for non-PEM input")
	}
}
