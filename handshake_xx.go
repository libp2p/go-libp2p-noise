package noise

import (
	"context"
	"fmt"

	"github.com/libp2p/go-libp2p-noise/core"
)

func (s *secureSession) runXXAsInitiator(ctx context.Context, payload []byte) error {
	// stage 0
	err := s.sendHandshakeMessage(nil)
	if err != nil {
		return fmt.Errorf("error sending handshake message: %s", err)
	}

	// stage 1
	// read reply
	_, plaintext, err := s.readHandshakeMessage()
	if err != nil {
		return fmt.Errorf("error reading handshake message: %s", err)
	}

	err = s.processRemoteHandshakePayload(plaintext)
	if err != nil {
		return fmt.Errorf("error processing remote handshake payload: %s", err)
	}

	// stage 2 //
	err = s.sendHandshakeMessage(payload)
	if err != nil {
		return fmt.Errorf("runHandshake_xx stage=2 initiator=true err=%s", err)
	}

	if s.noisePipesSupport {
		s.noiseStaticKeyCache.Store(s.remotePeer, s.ns.RemoteKey())
	}

	return nil
}

func (s *secureSession) runXXfallbackAsInitiator(ctx context.Context, payload []byte, ikMsg []byte, ikEphemeral *core.Keypair) error {
	// stage 0

	// get ephemeral key from previous IK NoiseSession
	e_xx := core.NewKeypair(ikEphemeral.PubKey(), ikEphemeral.PrivKey())

	// initialize state as if we sent the first message
	s.ns, _ = core.XXSendMessage(s.ns, nil, &e_xx)

	// stage 1
	msgbuf, err := core.XXDecode1(ikMsg)

	if err != nil {
		return fmt.Errorf("failed to decode handshake message: %s", err)
	}

	var plaintext []byte
	var valid bool
	s.ns, plaintext, valid = core.XXRecvMessage(s.ns, msgbuf)
	if !valid {
		return fmt.Errorf("handshake message invalid")
	}

	err = s.processRemoteHandshakePayload(plaintext)
	if err != nil {
		return fmt.Errorf("error processing remote handshake payload: %s", err)
	}

	// stage 2 //
	err = s.sendHandshakeMessage(payload)
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
	_, _, err := s.readHandshakeMessage()
	if err != nil {
		return fmt.Errorf("error reading handshake message: %s", err)
	}

	// stage 1 //
	err = s.sendHandshakeMessage(payload)
	if err != nil {
		return fmt.Errorf("runHandshake_xx stage=1 initiator=false err=%s", err)
	}

	// stage 2 //
	// read message
	var plaintext []byte
	_, plaintext, err = s.readHandshakeMessage()
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
	msgbuf, err := core.XXDecode0(ikMsg)
	if err != nil {
		return err
	}

	// "receive" the message, updating the noise session handshake state
	xx_msgbuf := core.NewMessageBuffer(msgbuf.NE(), nil, nil)
	var valid bool
	s.ns, _, valid = core.XXRecvMessage(s.ns, &xx_msgbuf)
	if !valid {
		return fmt.Errorf("runHandshake_xx validation fail")
	}

	// stage 1 //
	err = s.sendHandshakeMessage(payload)
	if err != nil {
		return fmt.Errorf("runHandshake_xx stage=1 initiator=false err=%s", err)
	}

	// stage 2 //
	// read message
	var plaintext []byte
	_, plaintext, err = s.readHandshakeMessage()
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
	// new XX noise session
	s.ns = core.XXInitSession(s.initiator, s.prologue, *s.noiseKeypair, [32]byte{})

	if s.initiator {
		return s.runXXAsInitiator(ctx, payload)
	}
	return s.runXXAsResponder(ctx, payload)
}

func (s *secureSession) runXXfallback(ctx context.Context, payload []byte, initialMsg []byte) (err error) {
	e := s.ns.Ephemeral()
	// new XX noise session
	s.ns = core.XXInitSession(s.initiator, s.prologue, *s.noiseKeypair, [32]byte{})

	if s.initiator {
		return s.runXXfallbackAsInitiator(ctx, payload, initialMsg, e)
	}
	return s.runXXfallbackAsResponder(ctx, payload, initialMsg)
}
