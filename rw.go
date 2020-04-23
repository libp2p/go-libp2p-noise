package noise

import (
	"encoding/binary"
	"fmt"
	"io"
)

// Each encrypted transport message must be <= 65,535 bytes, including 16
// bytes of authentication data. To write larger plaintexts, we split them
// into fragments of maxPlaintextLength before encrypting.
const maxPlaintextLength = 65519

// Read reads from the secure connection, filling `buf` with plaintext data.
// May read less than len(buf) if data is available immediately.
func (s *secureSession) Read(buf []byte) (int, error) {
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
		ciphertext, err := s.readMsgInsecure()
		if err != nil {
			return 0, err
		}

		plaintext, err := s.decrypt(ciphertext)
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

// Write encrypts the plaintext `in` data and sends it on the
// secure connection.
func (s *secureSession) Write(in []byte) (int, error) {
	s.writeLock.Lock()
	defer s.writeLock.Unlock()

	writeChunk := func(in []byte) (int, error) {
		ciphertext, err := s.encrypt(in)
		if err != nil {
			return 0, err
		}

		err = s.writeMsgInsecure(ciphertext)
		if err != nil {
			return 0, err
		}
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

// readMsgInsecure reads a message from the insecure channel.
// it first reads the message length, then consumes that many bytes
// from the insecure conn.
func (s *secureSession) readMsgInsecure() ([]byte, error) {
	buf := make([]byte, 2)
	_, err := io.ReadFull(s.insecure, buf)
	if err != nil {
		return nil, err
	}
	size := int(binary.BigEndian.Uint16(buf))
	buf = make([]byte, size)
	_, err = io.ReadFull(s.insecure, buf)
	return buf, err
}

// writeMsgInsecure writes to the insecure conn.
// data will be prefixed with its length in bytes, written as a 16-bit uint in network order.
func (s *secureSession) writeMsgInsecure(data []byte) error {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, uint16(len(data)))
	_, err := s.insecure.Write(buf)
	if err != nil {
		return fmt.Errorf("error writing length prefix: %w", err)
	}
	_, err = s.insecure.Write(data)
	return err
}
