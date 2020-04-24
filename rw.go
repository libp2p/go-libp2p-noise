package noise

import (
	"encoding/binary"
	"fmt"
	"io"

	pool "github.com/libp2p/go-buffer-pool"
	"golang.org/x/crypto/poly1305"
)

// MaxTransportMsgLength is the Noise-imposed maximum transport message length,
// inclusive of the MAC size (16 bytes, Poly1305 for noise-libp2p).
const MaxTransportMsgLength = 0xffff

// MaxPlaintextLength is the maximum payload size. It is MaxTransportMsgLength
// minus the MAC size. Payloads over this size will be automatically chunked.
const MaxPlaintextLength = MaxTransportMsgLength - poly1305.TagSize

// LengthPrefixLength is the length of the length prefix itself, which precedes
// all transport messages in order to delimit them. In bytes.
const LengthPrefixLength = 2

// Read reads from the secure connection, returning plaintext data in `buf`.
//
// Honours io.Reader in terms of behaviour.
func (s *secureSession) Read(buf []byte) (int, error) {
	s.readLock.Lock()
	defer s.readLock.Unlock()

	// 1. If we have queued received bytes:
	//   1a. If len(buf) < len(queued), saturate buf, update seek pointer, return.
	//   1b. If len(buf) >= len(queued), copy remaining to buf, release queued buffer back into pool, return.
	//
	// 2. Else, read the next message off the wire; next_len is length prefix.
	//   2a. If len(buf) >= next_len, copy the message to input buffer (zero-alloc path), and return.
	//   2b. If len(buf) < next_len, obtain buffer from pool, copy entire message into it, saturate buf, update seek pointer.
	var copied int
	if s.qbuf != nil {
		// we have queued bytes; copy as much as we can.
		copied = copy(buf, s.qbuf[s.qseek:])
		if copied == s.qrem {
			// queued buffer is now empty, reset and release.
			pool.Put(s.qbuf)
			s.qseek, s.qrem, s.qbuf = 0, 0, nil
		} else {
			// we copied less than we had; update seek and rem.
			s.qseek, s.qrem = s.qseek+copied, s.qrem-copied
		}
		return copied, nil
	}

	// cbuf is the ciphertext buffer.
	cbuf, err := s.readMsgInsecure()
	if err != nil {
		return 0, err
	}
	defer pool.Put(cbuf)

	// plen is the payload length: the transport message size minus the authentication tag.
	plen := len(cbuf) - poly1305.TagSize

	// if the reader is willing to read at least as many bytes as we are receiving,
	// decrypt the message directly into the buffer (zero-alloc path).
	if len(buf) >= plen {
		if _, err := s.decrypt(buf[:0], cbuf); err != nil {
			return 0, err
		}
		return plen, nil
	}

	// otherwise, get a buffer from the pool so we can stash the payload.
	s.qbuf = pool.Get(plen)
	if _, err = s.decrypt(s.qbuf[:0], cbuf); err != nil {
		return 0, err
	}

	// copy as many bytes as we can.
	copied = copy(buf, s.qbuf)

	// update seek and remaining pointers.
	s.qseek, s.qrem = copied, plen-copied
	return copied, nil
}

// Write encrypts the plaintext `in` data and sends it on the
// secure connection.
func (s *secureSession) Write(buf []byte) (int, error) {
	s.writeLock.Lock()
	defer s.writeLock.Unlock()

	var (
		written int
		cbuf    []byte
		total   = len(buf)
	)

	if total < MaxPlaintextLength {
		cbuf = pool.Get(total + poly1305.TagSize)
	} else {
		cbuf = pool.Get(MaxTransportMsgLength)
	}
	defer pool.Put(cbuf)

	for written < total {
		end := written + MaxPlaintextLength
		if end > total {
			end = total
		}

		b, err := s.encrypt(cbuf[:0], buf[written:end])
		if err != nil {
			return 0, err
		}

		_, err = s.writeMsgInsecure(b)
		if err != nil {
			return written, err
		}
		written = end
	}
	return written, nil
}

// readMsgInsecure reads a message from the insecure channel.
// it first reads the message length, then consumes that many bytes
// from the insecure conn.
func (s *secureSession) readMsgInsecure() ([]byte, error) {
	_, err := io.ReadFull(s.insecure, s.rlen)
	if err != nil {
		return nil, err
	}
	size := int(binary.BigEndian.Uint16(s.rlen))
	buf := pool.Get(size)
	_, err = io.ReadFull(s.insecure, buf)
	return buf, err
}

// writeMsgInsecure writes to the insecure conn.
// data will be prefixed with its length in bytes, written as a 16-bit uint in network order.
func (s *secureSession) writeMsgInsecure(data []byte) (int, error) {
	// we rather stage the length-prefixed write in a buffer to then call Write
	// on the underlying transport at once, rather than Write twice and likely
	// induce transport-level fragmentation.
	l := len(data)
	buf := pool.Get(LengthPrefixLength + l)
	defer pool.Put(buf)

	// length-prefix || data
	binary.BigEndian.PutUint16(buf, uint16(l))
	n := copy(buf[LengthPrefixLength:], data)
	if n != l {
		return 0, fmt.Errorf("assertion failed during noise secure channel write; expected to copy %d bytes, copied: %d", l, n)
	}
	return s.insecure.Write(buf)
}
