package noise

import (
	"errors"
	xx "github.com/libp2p/go-libp2p-noise/xx"
)

func (s *secureSession) Encrypt(plaintext []byte) (ciphertext []byte, err error) {
	if !s.handshakeComplete {
		return nil, errors.New("encrypt err: haven't completed handshake")
	}

	if s.initiator {
		cs := s.ns.CS1()
		_, ciphertext = xx.EncryptWithAd(cs, nil, plaintext)
	} else {
		cs := s.ns.CS2()
		_, ciphertext = xx.EncryptWithAd(cs, nil, plaintext)
	}

	return ciphertext, nil
}

func (s *secureSession) Decrypt(ciphertext []byte) (plaintext []byte, err error) {
	var ok bool
	if !s.handshakeComplete {
		return nil, errors.New("decrypt err: haven't completed handshake")
	}

	if s.initiator {
		cs := s.ns.CS2()
		_, plaintext, ok = xx.DecryptWithAd(cs, nil, ciphertext)
	} else {
		cs := s.ns.CS1()
		_, plaintext, ok = xx.DecryptWithAd(cs, nil, ciphertext)
	}

	if !ok {
		return nil, errors.New("decrypt err: could not decrypt")
	}

	return plaintext, nil
}
