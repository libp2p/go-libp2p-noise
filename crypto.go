package noise

import "errors"

func (s *secureSession) Encrypt(plaintext []byte) (ciphertext []byte, err error) {
	if s.ns.enc == nil {
		return nil, errors.New("cannot encrypt, handshake incomplete")
	}

	// TODO: use pre-allocated buffers
	ciphertext = s.ns.enc.Encrypt(nil, nil, plaintext)
	return ciphertext, nil
}

func (s *secureSession) Decrypt(ciphertext []byte) (plaintext []byte, err error) {
	if s.ns.dec == nil {
		return nil, errors.New("cannot decrypt, handshake incomplete")
	}

	// TODO: use pre-allocated buffers
	return s.ns.dec.Decrypt(nil, nil, ciphertext)
}
