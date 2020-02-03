/*
IK:
    <- s
    ...
    -> e, es, s, ss
    <- e, ee, se
*/

// Implementation Version: 1.0.0

/* ---------------------------------------------------------------- *
 * PARAMETERS                                                       *
 * ---------------------------------------------------------------- */

package handshake

import "errors"

/* HandshakeState */

func ikInitializeInitiator(prologue []byte, s Keypair, rs [32]byte, psk [32]byte) handshakestate {
	var ss symmetricstate
	var e Keypair
	var re [32]byte
	name := []byte("Noise_IK_25519_ChaChaPoly_SHA256")
	ss = initializeSymmetric(name)
	mixHash(&ss, prologue)
	mixHash(&ss, rs[:])
	return handshakestate{ss, s, e, rs, re, psk}
}

func ikInitializeResponder(prologue []byte, s Keypair, rs [32]byte, psk [32]byte) handshakestate {
	var ss symmetricstate
	var e Keypair
	var re [32]byte
	name := []byte("Noise_IK_25519_ChaChaPoly_SHA256")
	ss = initializeSymmetric(name)
	mixHash(&ss, prologue)
	mixHash(&ss, s.publicKey[:])
	return handshakestate{ss, s, e, rs, re, psk}
}

func ikWriteMessageA(hs *handshakestate, payload []byte) (*handshakestate, MessageBuffer) {
	ne, ns, ciphertext := emptyKey, []byte{}, []byte{}
	hs.e = GenerateKeypair()
	ne = hs.e.publicKey
	mixHash(&hs.ss, ne[:])
	/* No PSK, so skipping mixKey */
	mixKey(&hs.ss, dh(hs.e.privateKey, hs.rs))
	spk := make([]byte, len(hs.s.publicKey))
	copy(spk[:], hs.s.publicKey[:])
	_, ns = encryptAndHash(&hs.ss, spk)
	mixKey(&hs.ss, dh(hs.s.privateKey, hs.rs))
	_, ciphertext = encryptAndHash(&hs.ss, payload)
	messageBuffer := MessageBuffer{ne, ns, ciphertext}
	return hs, messageBuffer
}

func ikWriteMessageB(hs *handshakestate, payload []byte) ([32]byte, MessageBuffer, cipherstate, cipherstate) {
	ne, ns, ciphertext := emptyKey, []byte{}, []byte{}
	hs.e = GenerateKeypair()
	ne = hs.e.publicKey
	mixHash(&hs.ss, ne[:])
	/* No PSK, so skipping mixKey */
	mixKey(&hs.ss, dh(hs.e.privateKey, hs.re))
	mixKey(&hs.ss, dh(hs.e.privateKey, hs.rs))
	_, ciphertext = encryptAndHash(&hs.ss, payload)
	messageBuffer := MessageBuffer{ne, ns, ciphertext}
	cs1, cs2 := split(&hs.ss)
	return hs.ss.h, messageBuffer, cs1, cs2
}

func ikReadMesssageA(hs *handshakestate, message *MessageBuffer) (*handshakestate, []byte, bool) {
	valid1 := true
	if validatePublicKey(message.ne[:]) {
		hs.re = message.ne
	}
	mixHash(&hs.ss, hs.re[:])
	/* No PSK, so skipping mixKey */
	mixKey(&hs.ss, dh(hs.s.privateKey, hs.re))
	_, ns, valid1 := decryptAndHash(&hs.ss, message.ns)
	if valid1 && len(ns) == 32 && validatePublicKey(message.ns[:]) {
		copy(hs.rs[:], ns)
	}
	mixKey(&hs.ss, dh(hs.s.privateKey, hs.rs))
	_, plaintext, valid2 := decryptAndHash(&hs.ss, message.ciphertext)
	return hs, plaintext, (valid1 && valid2)
}

func ikReadMessageB(hs *handshakestate, message *MessageBuffer) ([32]byte, []byte, bool, cipherstate, cipherstate) {
	valid1 := true
	if validatePublicKey(message.ne[:]) {
		hs.re = message.ne
	}
	mixHash(&hs.ss, hs.re[:])
	/* No PSK, so skipping mixKey */
	mixKey(&hs.ss, dh(hs.e.privateKey, hs.re))
	mixKey(&hs.ss, dh(hs.s.privateKey, hs.re))
	_, plaintext, valid2 := decryptAndHash(&hs.ss, message.ciphertext)
	cs1, cs2 := split(&hs.ss)
	return hs.ss.h, plaintext, (valid1 && valid2), cs1, cs2
}

/* ---------------------------------------------------------------- *
 * UTILITY FUNCTIONS                                                *
 * ---------------------------------------------------------------- */

// Encodes a MessageBuffer from stage 0
func IKEncode0(mb *MessageBuffer) []byte {
	enc := []byte{}

	enc = append(enc, mb.ne[:]...)
	enc = append(enc, mb.ns...)
	enc = append(enc, mb.ciphertext...)

	return enc
}

// Encodes a MessageBuffer from stage 1
func IKEncode1(mb *MessageBuffer) []byte {
	enc := []byte{}

	enc = append(enc, mb.ne[:]...)
	enc = append(enc, mb.ciphertext...)

	return enc
}

// Decodes initial message (stage 0) into MessageBuffer
func IKDecode0(in []byte) (*MessageBuffer, error) {
	if len(in) < 80 {
		return nil, errors.New("cannot decode stage 0 MessageBuffer: length less than 80 bytes")
	}

	mb := new(MessageBuffer)
	copy(mb.ne[:], in[:32])
	mb.ns = in[32:80]
	mb.ciphertext = in[80:]

	return mb, nil
}

// Decodes messages at stage 1 into MessageBuffer
func IKDecode1(in []byte) (*MessageBuffer, error) {
	if len(in) < 32 {
		return nil, errors.New("cannot decode stage 1 MessageBuffer: length less than 32 bytes")
	}

	mb := new(MessageBuffer)
	copy(mb.ne[:], in[:32])
	mb.ciphertext = in[32:]

	return mb, nil
}

/* ---------------------------------------------------------------- *
 * PROCESSES                                                        *
 * ---------------------------------------------------------------- */

func IKInitSession(initiator bool, prologue []byte, s Keypair, rs [32]byte) *NoiseSession {
	var session NoiseSession
	psk := emptyKey
	if initiator {
		session.hs = ikInitializeInitiator(prologue, s, rs, psk)
	} else {
		session.hs = ikInitializeResponder(prologue, s, rs, psk)
	}
	session.i = initiator
	session.mc = 0
	return &session
}

func IKSendMessage(session *NoiseSession, message []byte, _ *Keypair) (*NoiseSession, MessageBuffer) {
	var messageBuffer MessageBuffer
	if session.mc == 0 {
		_, messageBuffer = ikWriteMessageA(&session.hs, message)
	}
	if session.mc == 1 {
		session.h, messageBuffer, session.cs1, session.cs2 = ikWriteMessageB(&session.hs, message)
	}
	session.mc = session.mc + 1
	return session, messageBuffer
}

func IKRecvMessage(session *NoiseSession, message *MessageBuffer) (*NoiseSession, []byte, bool) {
	var plaintext []byte
	var valid bool
	if session.mc == 0 {
		_, plaintext, valid = ikReadMesssageA(&session.hs, message)
	}
	if session.mc == 1 {
		session.h, plaintext, valid, session.cs1, session.cs2 = ikReadMessageB(&session.hs, message)
	}
	session.mc = session.mc + 1
	return session, plaintext, valid
}
