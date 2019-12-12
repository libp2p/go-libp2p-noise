package noise

import (
	"crypto/rand"
	"golang.org/x/crypto/curve25519"
)

// Keypair is a noise ed25519 public-private keypair
type Keypair struct {
	publicKey  [32]byte
	privateKey [32]byte
}

// GenerateKeypair creates a new ed25519 keypair
func GenerateKeypair() (*Keypair, error) {
	var publicKey [32]byte
	var privateKey [32]byte
	_, err := rand.Read(privateKey[:])
	if err != nil {
		return nil, err
	}
	curve25519.ScalarBaseMult(&publicKey, &privateKey)
	return &Keypair{publicKey, privateKey}, nil
}
