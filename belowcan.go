package belowcan

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"

	"golang.org/x/crypto/ssh"
)

func Main() int {
	slog.Debug("belowcan", "test", true)

	priv, pub, err := GenerateAndPersistEd25519KeyPair("", "")
	if err != nil {
		slog.Error("GenerateAndPersistEd25519KeyPair", "error", err)
		return 1
	}

	slog.Debug("ed25519", "private key", priv)
	slog.Debug("ed25519", "public key", pub)

	return 0
}

func GenerateAndPersistEd25519KeyPair(privKeyPath, pubKeyPath string) (string, string, error) {
	if privKeyPath == "" {
		privKeyPath = "id_ed25519"
	}
	if pubKeyPath == "" {
		pubKeyPath = fmt.Sprintf("%s.pub", privKeyPath)
	}

	privString, pubString, err := Ed25519KeyPairToString()
	if err != nil {
		return "", "", err
	}

	if err := os.WriteFile(privKeyPath, []byte(privString), 0o600); err != nil {
		return "", "", err
	}

	if err := os.WriteFile(pubKeyPath, []byte(pubString), 0o600); err != nil {
		return "", "", err
	}

	return privString, pubString, nil
}

func generateEd25519KeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	return pub, priv, nil
}

func Ed25519KeyPairToString() (string, string, error) {
	pubEd25519Key, privEd25519Key, err := generateEd25519KeyPair()
	if err != nil {
		return "", "", err
	}

	pubSSHKeyStr, err := ed25519PublicKeyToString(pubEd25519Key)
	if err != nil {
		return "", "", err
	}

	privKeyPemStr, err := ed25519PrivateKeyToString(privEd25519Key)
	if err != nil {
		return "", "", err
	}

	return privKeyPemStr, pubSSHKeyStr, nil
}

func ed25519PublicKeyToString(pubEd25519Key ed25519.PublicKey) (string, error) {
	sshKey, err := ssh.NewPublicKey(pubEd25519Key)
	if err != nil {
		return "", err
	}

	keyBytes := sshKey.Marshal()
	keyBase64 := base64.StdEncoding.EncodeToString(keyBytes)

	sshKeyStr := "ssh-ed25519" + " " + keyBase64

	return sshKeyStr, nil
}

func ed25519PrivateKeyToString(privEd25519Key ed25519.PrivateKey) (string, error) {
	key := crypto.PrivateKey(privEd25519Key)

	keyPemBlock, err := ssh.MarshalPrivateKey(key, "")
	if err != nil {
		return "", err
	}

	keyPemStr := string(pem.EncodeToMemory(keyPemBlock))

	return keyPemStr, nil
}
