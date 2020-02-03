package noise

import (
	"errors"
	"github.com/libp2p/go-libp2p-noise/handshake"
)

func (s *secureSession) Encrypt(plaintext []byte) (ciphertext []byte, err error) {
	if s.xx_complete {
		if s.initiator {
			cs := s.xx_ns.CS1()
			_, ciphertext = handshake.EncryptWithAd(cs, nil, plaintext)
		} else {
			cs := s.xx_ns.CS2()
			_, ciphertext = handshake.EncryptWithAd(cs, nil, plaintext)
		}
	} else if s.ik_complete {
		if s.initiator {
			cs := s.ik_ns.CS1()
			_, ciphertext = handshake.EncryptWithAd(cs, nil, plaintext)
		} else {
			cs := s.ik_ns.CS2()
			_, ciphertext = handshake.EncryptWithAd(cs, nil, plaintext)
		}
	} else {
		return nil, errors.New("encrypt err: haven't completed handshake")
	}

	return ciphertext, nil
}

func (s *secureSession) Decrypt(ciphertext []byte) (plaintext []byte, err error) {
	var ok bool
	if s.xx_complete {
		if s.initiator {
			cs := s.xx_ns.CS2()
			_, plaintext, ok = handshake.DecryptWithAd(cs, nil, ciphertext)
		} else {
			cs := s.xx_ns.CS1()
			_, plaintext, ok = handshake.DecryptWithAd(cs, nil, ciphertext)
		}
	} else if s.ik_complete {
		if s.initiator {
			cs := s.ik_ns.CS2()
			_, plaintext, ok = handshake.DecryptWithAd(cs, nil, ciphertext)
		} else {
			cs := s.ik_ns.CS1()
			_, plaintext, ok = handshake.DecryptWithAd(cs, nil, ciphertext)
		}
	} else {
		return nil, errors.New("decrypt err: haven't completed handshake")
	}

	if !ok {
		return nil, errors.New("decrypt err: could not decrypt")
	}

	return plaintext, nil
}
