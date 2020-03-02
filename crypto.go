package noise

import "errors"

func (s *secureSession) Encrypt(plaintext []byte) (ciphertext []byte, err error) {
	if !s.handshakeComplete {
		return nil, errors.New("encrypt err: haven't completed handshake")
	}

	// TODO: use pre-allocated buffers
	ciphertext = s.enc.Encrypt(nil, nil, plaintext)
	return ciphertext, nil
}

func (s *secureSession) Decrypt(ciphertext []byte) (plaintext []byte, err error) {
	if !s.handshakeComplete {
		return nil, errors.New("decrypt err: haven't completed handshake")
	}

	// TODO: use pre-allocated buffers
	return s.dec.Decrypt(nil, nil, ciphertext)
}
