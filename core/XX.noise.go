/*
XX:
  -> e
  <- e, ee, s, es
  -> s, se
*/

// Implementation Version: 1.0.0

/* ---------------------------------------------------------------- *
 * PARAMETERS                                                       *
 * ---------------------------------------------------------------- */

package core

import "errors"

/* HandshakeState */

func xxInitializeInitiator(prologue []byte, s Keypair, rs [32]byte, psk [32]byte) handshakestate {
	var ss symmetricstate
	var e Keypair
	var re [32]byte
	name := []byte("Noise_XX_25519_ChaChaPoly_SHA256")
	ss = initializeSymmetric(name)
	mixHash(&ss, prologue)
	return handshakestate{ss, s, e, rs, re, psk}
}

func xxInitializeResponder(prologue []byte, s Keypair, rs [32]byte, psk [32]byte) handshakestate {
	var ss symmetricstate
	var e Keypair
	var re [32]byte
	name := []byte("Noise_XX_25519_ChaChaPoly_SHA256")
	ss = initializeSymmetric(name)
	mixHash(&ss, prologue)
	return handshakestate{ss, s, e, rs, re, psk}
}

func xxWriteMessageA(hs *handshakestate, payload []byte, e *Keypair) (*handshakestate, MessageBuffer) {
	ne, ns, ciphertext := emptyKey, []byte{}, []byte{}

	if e == nil {
		hs.e = GenerateKeypair()
	} else {
		hs.e = *e
	}

	ne = hs.e.publicKey
	mixHash(&hs.ss, ne[:])
	/* No PSK, so skipping mixKey */
	_, ciphertext = encryptAndHash(&hs.ss, payload)
	messageBuffer := MessageBuffer{ne, ns, ciphertext}
	return hs, messageBuffer
}

func xxWriteMessageB(hs *handshakestate, payload []byte) (*handshakestate, MessageBuffer) {
	ne, ns, ciphertext := emptyKey, []byte{}, []byte{}
	hs.e = GenerateKeypair()
	ne = hs.e.publicKey
	mixHash(&hs.ss, ne[:])
	/* No PSK, so skipping mixKey */
	mixKey(&hs.ss, dh(hs.e.privateKey, hs.re))
	spk := make([]byte, len(hs.s.publicKey))
	copy(spk[:], hs.s.publicKey[:])
	_, ns = encryptAndHash(&hs.ss, spk)
	mixKey(&hs.ss, dh(hs.s.privateKey, hs.re))
	_, ciphertext = encryptAndHash(&hs.ss, payload)
	messageBuffer := MessageBuffer{ne, ns, ciphertext}
	return hs, messageBuffer
}

func xxWriteMessageC(hs *handshakestate, payload []byte) ([32]byte, MessageBuffer, cipherstate, cipherstate) {
	ne, ns, ciphertext := emptyKey, []byte{}, []byte{}
	spk := make([]byte, len(hs.s.publicKey))
	copy(spk[:], hs.s.publicKey[:])
	_, ns = encryptAndHash(&hs.ss, spk)
	mixKey(&hs.ss, dh(hs.s.privateKey, hs.re))
	_, ciphertext = encryptAndHash(&hs.ss, payload)
	messageBuffer := MessageBuffer{ne, ns, ciphertext}
	cs1, cs2 := split(&hs.ss)
	return hs.ss.h, messageBuffer, cs1, cs2
}

func xxReadMessageA(hs *handshakestate, message *MessageBuffer) (*handshakestate, []byte, bool) {
	valid1 := true
	if validatePublicKey(message.ne[:]) {
		hs.re = message.ne
	}
	mixHash(&hs.ss, hs.re[:])
	/* No PSK, so skipping mixKey */
	_, plaintext, valid2 := decryptAndHash(&hs.ss, message.ciphertext)
	return hs, plaintext, (valid1 && valid2)
}

func xxReadMessageB(hs *handshakestate, message *MessageBuffer) (*handshakestate, []byte, bool) {
	valid1 := true
	if validatePublicKey(message.ne[:]) {
		hs.re = message.ne
	}
	mixHash(&hs.ss, hs.re[:])
	/* No PSK, so skipping mixKey */
	mixKey(&hs.ss, dh(hs.e.privateKey, hs.re))
	_, ns, valid1 := decryptAndHash(&hs.ss, message.ns)
	if valid1 && len(ns) == 32 && validatePublicKey(message.ns[:]) {
		copy(hs.rs[:], ns)
	}
	mixKey(&hs.ss, dh(hs.e.privateKey, hs.rs))
	_, plaintext, valid2 := decryptAndHash(&hs.ss, message.ciphertext)
	return hs, plaintext, (valid1 && valid2)
}

func xxReadMessageC(hs *handshakestate, message *MessageBuffer) ([32]byte, []byte, bool, cipherstate, cipherstate) {
	valid1 := true
	_, ns, valid1 := decryptAndHash(&hs.ss, message.ns)
	if valid1 && len(ns) == 32 && validatePublicKey(message.ns[:]) {
		copy(hs.rs[:], ns)
	}
	mixKey(&hs.ss, dh(hs.e.privateKey, hs.rs))
	_, plaintext, valid2 := decryptAndHash(&hs.ss, message.ciphertext)
	cs1, cs2 := split(&hs.ss)
	return hs.ss.h, plaintext, (valid1 && valid2), cs1, cs2
}

type xxCodec struct{}

var _ HandshakeCodec = (*xxCodec)(nil)

func (x xxCodec) Decode0(in []byte) (*MessageBuffer, error) {
	if len(in) < 32 {
		return nil, errors.New("cannot decode stage 0 MessageBuffer: length less than 32 bytes")
	}

	mb := new(MessageBuffer)
	copy(mb.ne[:], in[:32])
	mb.ciphertext = in[32:]

	return mb, nil
}

func (x xxCodec) Decode1(in []byte) (*MessageBuffer, error) {
	if len(in) < 80 {
		return nil, errors.New("cannot decode stage 1/2 MessageBuffer: length less than 96 bytes")
	}

	mb := new(MessageBuffer)
	copy(mb.ne[:], in[:32])
	mb.ns = in[32:80]
	mb.ciphertext = in[80:]

	return mb, nil
}

func (x xxCodec) Encode0(mb *MessageBuffer) []byte {
	enc := []byte{}

	enc = append(enc, mb.ne[:]...)
	enc = append(enc, mb.ciphertext...)

	return enc
}

func (x xxCodec) Encode1(mb *MessageBuffer) []byte {
	enc := []byte{}

	enc = append(enc, mb.ne[:]...)
	enc = append(enc, mb.ns...)
	enc = append(enc, mb.ciphertext...)

	return enc
}

func (x xxCodec) AcceptMessageBuffer(s *NoiseSession, msg *MessageBuffer) (plaintext []byte, valid bool) {
	if s.mc == 0 {
		_, plaintext, valid = xxReadMessageA(&s.hs, msg)
	}
	if s.mc == 1 {
		_, plaintext, valid = xxReadMessageB(&s.hs, msg)
	}
	if s.mc == 2 {
		s.h, plaintext, valid, s.cs1, s.cs2 = xxReadMessageC(&s.hs, msg)
	}
	s.mc = s.mc + 1
	return plaintext, valid
}

func (x xxCodec) PrepareMessageBuffer(s *NoiseSession, msg []byte, ephemeral *Keypair) MessageBuffer {
	var messageBuffer MessageBuffer
	if s.mc == 0 {
		_, messageBuffer = xxWriteMessageA(&s.hs, msg, ephemeral)
	}
	if s.mc == 1 {
		_, messageBuffer = xxWriteMessageB(&s.hs, msg)
	}
	if s.mc == 2 {
		s.h, messageBuffer, s.cs1, s.cs2 = xxWriteMessageC(&s.hs, msg)
	}
	s.mc = s.mc + 1
	return messageBuffer
}

func XXInitSession(initiator bool, prologue []byte, s Keypair, rs [32]byte) *NoiseSession {
	var session NoiseSession
	psk := emptyKey
	if initiator {
		session.hs = xxInitializeInitiator(prologue, s, rs, psk)
	} else {
		session.hs = xxInitializeResponder(prologue, s, rs, psk)
	}
	session.i = initiator
	session.mc = 0
	session.codec = xxCodec{}
	return &session
}

func XXfallbackInitSession(initiator bool, prologue []byte, s Keypair, rs [32]byte, ikMsg []byte, ikEphemeral *Keypair) (*NoiseSession, []byte, error) {
	var session NoiseSession
	psk := emptyKey
	if initiator {
		session.hs = xxInitializeInitiator(prologue, s, rs, psk)
	} else {
		session.hs = xxInitializeResponder(prologue, s, rs, psk)
	}
	session.i = initiator
	session.codec = xxCodec{}

	var plaintext []byte
	if initiator {
		// initialize XXfallback state as if we sent stage 0 message,
		// using ephemeral key from failed IK session
		xxWriteMessageA(&session.hs, nil, ikEphemeral)

		// decode response as stage 1 XX message and incorporate into
		// handshake state
		msgbuf, err := session.codec.Decode1(ikMsg)
		if err != nil {
			return nil, nil, err
		}
		var valid bool
		_, plaintext, valid = xxReadMessageB(&session.hs, msgbuf)
		if !valid {
			return nil, plaintext, errors.New("unable to initialize XXfallback - invalid stage 1 message")
		}
		session.mc = 2
	} else {
		// decode message as stage 0 XX message and incorporate into
		// handshake state
		msgbuf, err := session.codec.Decode0(ikMsg)
		if err != nil {
			return nil, nil, err
		}
		xxMsgbuf := NewMessageBuffer(msgbuf.NE(), nil, nil)
		var valid bool
		_, plaintext, valid = xxReadMessageA(&session.hs, &xxMsgbuf)
		if !valid {
			return nil, nil, errors.New("unable to initialize XXfallback - invalid stage 0 message")
		}
		session.mc = 1
	}

	return &session, plaintext, nil
}

func XXSendMessage(session *NoiseSession, message []byte, ephemeral *Keypair) (*NoiseSession, MessageBuffer) {
	var messageBuffer MessageBuffer
	if session.mc == 0 {
		_, messageBuffer = xxWriteMessageA(&session.hs, message, ephemeral)
	}
	if session.mc == 1 {
		_, messageBuffer = xxWriteMessageB(&session.hs, message)
	}
	if session.mc == 2 {
		session.h, messageBuffer, session.cs1, session.cs2 = xxWriteMessageC(&session.hs, message)
		//session.hs = handshakestate{}
	}
	session.mc = session.mc + 1
	return session, messageBuffer
}

func XXRecvMessage(session *NoiseSession, message *MessageBuffer) (*NoiseSession, []byte, bool) {
	var plaintext []byte
	var valid bool
	if session.mc == 0 {
		_, plaintext, valid = xxReadMessageA(&session.hs, message)
	}
	if session.mc == 1 {
		_, plaintext, valid = xxReadMessageB(&session.hs, message)
	}
	if session.mc == 2 {
		session.h, plaintext, valid, session.cs1, session.cs2 = xxReadMessageC(&session.hs, message)
		//session.hs = handshakestate{}
	}
	session.mc = session.mc + 1
	return session, plaintext, valid
}
