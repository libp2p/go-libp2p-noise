package noise

import (
	"encoding/binary"
	"io"
)

func (s *secureSession) readLength() (int, error) {
	buf := make([]byte, 2)
	_, err := io.ReadFull(s.insecure, buf)
	return int(binary.BigEndian.Uint16(buf)), err
}

func (s *secureSession) writeLength(length int) error {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, uint16(length))
	_, err := s.insecure.Write(buf)
	return err
}

func (s *secureSession) readSecure(buf []byte) (int, error) {
	s.readLock.Lock()
	defer s.readLock.Unlock()

	l := len(buf)

	// if we have previously unread bytes, and they fit into the buf, copy them over and return
	if l <= len(s.msgBuffer) {
		copy(buf, s.msgBuffer)
		s.msgBuffer = s.msgBuffer[l:]
		return l, nil
	}

	readChunk := func(buf []byte) (int, error) {
		// read length of encrypted message
		l, err := s.readLength()
		if err != nil {
			return 0, err
		}

		// read and decrypt ciphertext
		ciphertext := make([]byte, l)
		_, err = io.ReadFull(s.insecure, ciphertext)
		if err != nil {
			return 0, err
		}

		plaintext, err := s.Decrypt(ciphertext)
		if err != nil {
			return 0, err
		}

		// append plaintext to message buffer, copy over what can fit in the buf
		// then advance message buffer to remove what was copied
		s.msgBuffer = append(s.msgBuffer, plaintext...)
		c := copy(buf, s.msgBuffer)
		s.msgBuffer = s.msgBuffer[c:]
		return c, nil
	}

	total := 0
	for i := 0; i < len(buf); i += maxPlaintextLength {
		end := i + maxPlaintextLength
		if end > len(buf) {
			end = len(buf)
		}

		c, err := readChunk(buf[i:end])
		total += c
		if err != nil {
			return total, err
		}
	}

	return total, nil
}

func (s *secureSession) writeSecure(in []byte) (int, error) {
	s.writeLock.Lock()
	defer s.writeLock.Unlock()

	writeChunk := func(in []byte) (int, error) {
		ciphertext, err := s.Encrypt(in)
		if err != nil {
			return 0, err
		}

		err = s.writeLength(len(ciphertext))
		if err != nil {
			return 0, err
		}

		_, err = s.insecure.Write(ciphertext)
		return len(in), err
	}

	written := 0
	for i := 0; i < len(in); i += maxPlaintextLength {
		end := i + maxPlaintextLength
		if end > len(in) {
			end = len(in)
		}

		l, err := writeChunk(in[i:end])
		written += l
		if err != nil {
			return written, err
		}
	}
	return written, nil
}
