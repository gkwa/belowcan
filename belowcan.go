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
	run()

	return 0
}

func run() {
	privKeyPath := "id_ed25519"
	pubKeyPath := fmt.Sprintf("%s.pub", privKeyPath)

	privString, pubString, err := GenEd25519Pair()
	if err != nil {
		panic(err)
	}

	slog.Debug("ed25519", "private key", privString, "path", privKeyPath)
	slog.Debug("ed25519", "public key", pubString, "path", pubKeyPath)

	err = saveToPath(privString, privKeyPath)
	if err != nil {
		panic(err)
	}

	err = saveToPath(pubString, pubKeyPath)
	if err != nil {
		panic(err)
	}
}

func saveToPath(content, path string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.WriteString(content)
	if err != nil {
		return err
	}

	return nil
}

func GenEd25519Pair() (string, string, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	p, err := ssh.MarshalPrivateKey(crypto.PrivateKey(priv), "")
	if err != nil {
		return "", "", err
	}
	privateKeyPem := pem.EncodeToMemory(p)
	privateKeyString := string(privateKeyPem)
	publicKey, err := ssh.NewPublicKey(pub)
	if err != nil {
		return "", "", err
	}
	publicKeyString := "ssh-ed25519" + " " + base64.StdEncoding.EncodeToString(publicKey.Marshal())

	return privateKeyString, publicKeyString, nil
}
