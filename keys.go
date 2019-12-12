package noise

import (
	"crypto/rand"
	"golang.org/x/crypto/curve25519"
)

// Keypair is a noise ed25519 public-private keypair
type Keypair struct {
	public_key  [32]byte
	private_key [32]byte
}

// GenerateKeypair creates a new ed25519 keypair
func GenerateKeypair() (*Keypair, error) {
	var public_key [32]byte
	var private_key [32]byte
	_, err := rand.Read(private_key[:])
	if err != nil {
		return nil, err
	}
	curve25519.ScalarBaseMult(&public_key, &private_key)
	return &Keypair{public_key, private_key}, nil
}
