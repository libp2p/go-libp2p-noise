package noise

import "errors"

func (s *secureSession) Encrypt(plaintext []byte) (ciphertext []byte, err error) {
	if !s.xx_complete && !s.ik_complete {
		return nil, errors.New("decrypt err: haven't completed handshake")
	}

	ciphertext = s.ns.Encrypt(plaintext)
	return ciphertext, nil
}

func (s *secureSession) Decrypt(ciphertext []byte) (plaintext []byte, err error) {
	if !s.xx_complete && !s.ik_complete {
		return nil, errors.New("decrypt err: haven't completed handshake")
	}

	return s.ns.Decrypt(ciphertext)
}
