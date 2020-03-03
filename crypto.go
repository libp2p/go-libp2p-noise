package noise

import "errors"

func (s *secureSession) encrypt(plaintext []byte) (ciphertext []byte, err error) {
	if s.enc == nil {
		return nil, errors.New("cannot encrypt, handshake incomplete")
	}

	// TODO: use pre-allocated buffers
	ciphertext = s.enc.Encrypt(nil, nil, plaintext)
	return ciphertext, nil
}

func (s *secureSession) decrypt(ciphertext []byte) (plaintext []byte, err error) {
	if s.dec == nil {
		return nil, errors.New("cannot decrypt, handshake incomplete")
	}

	// TODO: use pre-allocated buffers
	return s.dec.Decrypt(nil, nil, ciphertext)
}
