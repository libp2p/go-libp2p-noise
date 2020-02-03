package noise

import (
	"errors"
	"github.com/libp2p/go-libp2p-noise/handshake"
)

func (s *secureSession) Encrypt(plaintext []byte) (ciphertext []byte, err error) {
	if !s.xx_complete && !s.ik_complete {
		return nil, errors.New("decrypt err: haven't completed handshake")
	}

	if s.initiator {
		cs := s.ns.CS1()
		_, ciphertext = handshake.EncryptWithAd(cs, nil, plaintext)
	} else {
		cs := s.ns.CS2()
		_, ciphertext = handshake.EncryptWithAd(cs, nil, plaintext)
	}

	return ciphertext, nil
}

func (s *secureSession) Decrypt(ciphertext []byte) (plaintext []byte, err error) {
	if !s.xx_complete && !s.ik_complete {
		return nil, errors.New("decrypt err: haven't completed handshake")
	}

	var ok bool
	if s.initiator {
		cs := s.ns.CS2()
		_, plaintext, ok = handshake.DecryptWithAd(cs, nil, ciphertext)
	} else {
		cs := s.ns.CS1()
		_, plaintext, ok = handshake.DecryptWithAd(cs, nil, ciphertext)
	}

	if !ok {
		return nil, errors.New("decrypt err: could not decrypt")
	}

	return plaintext, nil
}
