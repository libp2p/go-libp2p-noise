package noise

import (
	"context"
	"fmt"
	"io"

	"github.com/libp2p/go-libp2p-noise/handshake"
)

type msgDecoder func([]byte) (*handshake.MessageBuffer, error)
type msgReceiver func(session *handshake.NoiseSession, buffer *handshake.MessageBuffer) (*handshake.NoiseSession, []byte, bool)
type msgEncoder func(buffer *handshake.MessageBuffer) []byte
type msgSender func(session *handshake.NoiseSession, payload []byte, ephemeral *handshake.Keypair) (*handshake.NoiseSession, handshake.MessageBuffer)

func (s *secureSession) recvHandshakeMessage(decoder msgDecoder, receiver msgReceiver) (encrypted []byte, plaintext []byte, err error) {
	l, err := s.readLength()
	if err != nil {
		return nil, nil, fmt.Errorf("xxRecvHandshakeMessage read length err=%s", err)
	}

	buf := make([]byte, l)

	_, err = io.ReadFull(s.insecure, buf)
	if err != nil {
		return buf, nil, err
	}

	var msgbuf *handshake.MessageBuffer
	msgbuf, err = decoder(buf)
	if err != nil {
		return buf, nil, err
	}
	var valid bool
	s.ns, plaintext, valid = receiver(s.ns, msgbuf)
	if !valid {
		return buf, nil, fmt.Errorf("handshake message invalid")
	}

	return buf, plaintext, nil
}

func (s *secureSession) sendHandshakeMessage(payload []byte, encoder msgEncoder, sender msgSender) error {
	var msgbuf handshake.MessageBuffer
	s.ns, msgbuf = sender(s.ns, payload, nil)
	encMsgBuf := encoder(&msgbuf)

	err := s.writeLength(len(encMsgBuf))
	if err != nil {
		return fmt.Errorf("xxSendHandshakeMessage write length err=%s", err)
	}

	_, err = s.insecure.Write(encMsgBuf)
	if err != nil {
		return fmt.Errorf("xxSendHandshakeMessage write to conn err=%s", err)
	}

	return nil
}

func (s *secureSession) xxRecvHandshakeMessage(stageZero bool) (encrypted []byte, plaintext []byte, err error) {
	if stageZero {
		return s.recvHandshakeMessage(handshake.XXDecode0, handshake.XXRecvMessage)
	}
	return s.recvHandshakeMessage(handshake.XXDecode1, handshake.XXRecvMessage)
}

func (s *secureSession) xxSendHandshakeMessage(payload []byte, initial_stage bool) error {
	if initial_stage {
		return s.sendHandshakeMessage(payload, handshake.XXEncode0, handshake.XXSendMessage)
	}
	return s.sendHandshakeMessage(payload, handshake.XXEncode1, handshake.XXSendMessage)
}

func (s *secureSession) runXXAsInitiator(ctx context.Context, payload []byte) error {
	// stage 0
	err := s.xxSendHandshakeMessage(nil, true)
	if err != nil {
		return fmt.Errorf("error sending handshake message: %s", err)
	}

	// stage 1
	// read reply
	_, plaintext, err := s.xxRecvHandshakeMessage(false)
	if err != nil {
		return fmt.Errorf("error reading handshake message: %s", err)
	}

	err = s.processRemoteHandshakePayload(plaintext)
	if err != nil {
		return fmt.Errorf("error processing remote handshake payload: %s", err)
	}

	// stage 2 //
	err = s.xxSendHandshakeMessage(payload, false)
	if err != nil {
		return fmt.Errorf("runHandshake_xx stage=2 initiator=true err=%s", err)
	}

	if s.noisePipesSupport {
		s.noiseStaticKeyCache.Store(s.remotePeer, s.ns.RemoteKey())
	}

	return nil
}

func (s *secureSession) runXXfallbackAsInitiator(ctx context.Context, payload []byte, ikMsg []byte) error {
	// stage 0

	// get ephemeral key from previous IK NoiseSession
	e_ik := s.ns.Ephemeral()
	e_xx := handshake.NewKeypair(e_ik.PubKey(), e_ik.PrivKey())

	// initialize state as if we sent the first message
	s.ns, _ = handshake.XXSendMessage(s.ns, nil, &e_xx)

	// stage 1
	msgbuf, err := handshake.XXDecode1(ikMsg)

	if err != nil {
		return fmt.Errorf("failed to decode handshake message: %s", err)
	}

	var plaintext []byte
	var valid bool
	s.ns, plaintext, valid = handshake.XXRecvMessage(s.ns, msgbuf)
	if !valid {
		return fmt.Errorf("handshake message invalid")
	}

	err = s.processRemoteHandshakePayload(plaintext)
	if err != nil {
		return fmt.Errorf("error processing remote handshake payload: %s", err)
	}

	// stage 2 //
	err = s.xxSendHandshakeMessage(payload, false)
	if err != nil {
		return fmt.Errorf("error sending handshake message: %s", err)
	}

	if s.noisePipesSupport {
		s.noiseStaticKeyCache.Store(s.remotePeer, s.ns.RemoteKey())
	}
	return nil
}

func (s *secureSession) runXXAsResponder(ctx context.Context, payload []byte) error {
	// stage 0
	// read message
	_, _, err := s.xxRecvHandshakeMessage(true)
	if err != nil {
		return fmt.Errorf("error reading handshake message: %s", err)
	}

	// stage 1 //
	err = s.xxSendHandshakeMessage(payload, false)
	if err != nil {
		return fmt.Errorf("runHandshake_xx stage=1 initiator=false err=%s", err)
	}

	// stage 2 //
	// read message
	var plaintext []byte
	_, plaintext, err = s.xxRecvHandshakeMessage(false)
	if err != nil {
		return fmt.Errorf("runHandshake_xx stage=2 initiator=false err=%s", err)
	}

	err = s.processRemoteHandshakePayload(plaintext)
	if err != nil {
		return fmt.Errorf("error processing remote handshake payload: %s", err)
	}

	if s.noisePipesSupport {
		s.noiseStaticKeyCache.Store(s.remotePeer, s.remote.noiseKey)
	}
	return nil
}

func (s *secureSession) runXXfallbackAsResponder(ctx context.Context, payload []byte, ikMsg []byte) error {
	// stage zero
	// decode IK message as if it were stage zero XX message
	msgbuf, err := handshake.XXDecode0(ikMsg)
	if err != nil {
		return err
	}

	// "receive" the message, updating the noise session handshake state
	xx_msgbuf := handshake.NewMessageBuffer(msgbuf.NE(), nil, nil)
	var valid bool
	s.ns, _, valid = handshake.XXRecvMessage(s.ns, &xx_msgbuf)
	if !valid {
		return fmt.Errorf("runHandshake_xx validation fail")
	}

	// stage 1 //
	err = s.xxSendHandshakeMessage(payload, false)
	if err != nil {
		return fmt.Errorf("runHandshake_xx stage=1 initiator=false err=%s", err)
	}

	// stage 2 //
	// read message
	var plaintext []byte
	_, plaintext, err = s.xxRecvHandshakeMessage(false)
	if err != nil {
		return fmt.Errorf("runHandshake_xx stage=2 initiator=false err=%s", err)
	}

	err = s.processRemoteHandshakePayload(plaintext)
	if err != nil {
		return fmt.Errorf("error processing remote handshake payload: %s", err)
	}

	if s.noisePipesSupport {
		s.noiseStaticKeyCache.Store(s.remotePeer, s.remote.noiseKey)
	}
	return nil
}

// Runs the XX handshake
// XX:
//   -> e
//   <- e, ee, s, es
//   -> s, se
func (s *secureSession) runXX(ctx context.Context, payload []byte) (err error) {
	kp := handshake.NewKeypair(s.noiseKeypair.publicKey, s.noiseKeypair.privateKey)

	// new XX noise session
	s.ns = handshake.XXInitSession(s.initiator, s.prologue, kp, [32]byte{})

	if s.initiator {
		return s.runXXAsInitiator(ctx, payload)
	}
	return s.runXXAsResponder(ctx, payload)
}

func (s *secureSession) runXXfallback(ctx context.Context, payload []byte, initialMsg []byte) (err error) {
	kp := handshake.NewKeypair(s.noiseKeypair.publicKey, s.noiseKeypair.privateKey)
	// new XX noise session
	s.ns = handshake.XXInitSession(s.initiator, s.prologue, kp, [32]byte{})

	if s.initiator {
		return s.runXXfallbackAsInitiator(ctx, payload, initialMsg)
	}
	return s.runXXfallbackAsResponder(ctx, payload, initialMsg)
}
