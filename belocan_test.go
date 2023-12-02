package belowcan

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateAndPersistEd25519Keys(t *testing.T) {
	privKeyPath := filepath.Join(os.TempDir(), "test_priv_key")
	pubKeyPath := filepath.Join(os.TempDir(), "test_pub_key")

	defer func() {
		os.Remove(privKeyPath)
		os.Remove(pubKeyPath)
	}()

	privKey, pubKey, err := GenerateAndPersistEd25519KeyPair(privKeyPath, pubKeyPath)
	if err != nil {
		t.Errorf("Error generating and persisting keys: %v", err)
	}

	if _, err := os.Stat(privKeyPath); os.IsNotExist(err) {
		t.Errorf("Private key file not created")
	}

	if _, err := os.Stat(pubKeyPath); os.IsNotExist(err) {
		t.Errorf("Public key file not created")
	}

	if privKey == "" {
		t.Errorf("Generated private key is empty")
	}

	if pubKey == "" {
		t.Errorf("Generated public key is empty")
	}
}

func TestGenEd25519KeyPair(t *testing.T) {
	privKey, pubKey, err := Ed25519KeyPairToString()
	if err != nil {
		t.Errorf("Error generating Ed25519 key pair: %v", err)
	}

	if privKey == "" {
		t.Errorf("Generated private key is empty")
	}

	if pubKey == "" {
		t.Errorf("Generated public key is empty")
	}
}
