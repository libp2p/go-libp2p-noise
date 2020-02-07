package noise

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

func (s *secureSession) writeMsgInsecure(data []byte) error {
	// TODO: throw if len(data) > max_uint16
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, uint16(len(data)))
	_, err := s.insecure.Write(buf)
	if err != nil {
		return fmt.Errorf("error writing message length: %s", err)
	}
	_, err = s.insecure.Write(data)
	if err != nil {
		return err
	}
	return nil
}

func (s *secureSession) readMsgInsecure() ([]byte, error) {
	buf := make([]byte, 2)
	_, err := io.ReadFull(s.insecure, buf)
	if err != nil {
		return nil, fmt.Errorf("error reading message length: %s", err)
	}
	size := int(binary.BigEndian.Uint16(buf))
	buf = make([]byte, size)
	_, err = io.ReadFull(s.insecure, buf)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

func (s *secureSession) readSecure(buf []byte) (int, error) {
	if !s.xx_complete && !s.ik_complete {
		return 0, errors.New("handshake incomplete")
	}

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
		// read and decrypt ciphertext
		ciphertext, err := s.readMsgInsecure()
		if err != nil {
			return 0, err
		}

		plaintext, err := s.ns.Decrypt(ciphertext)
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
	if !s.xx_complete && !s.ik_complete {
		return 0, errors.New("handshake incomplete")
	}

	s.writeLock.Lock()
	defer s.writeLock.Unlock()

	writeChunk := func(in []byte) (int, error) {
		ciphertext := s.ns.Encrypt(in)

		err := s.writeMsgInsecure(ciphertext)
		if err != nil {
			return 0, err
		}

		return len(in), nil
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
