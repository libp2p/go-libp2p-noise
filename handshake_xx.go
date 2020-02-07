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

func (s *secureSession) runXXfallbackAsInitiator(ctx context.Context, payload []byte, remotePayload []byte) error {
	// stage 0 of the regular XX flow is skipped when running XXfallback as the initiator,
	// as our previously sent stage 0 IK message will be used as the stage 0 XX message

	// the responder's stage 1 message is read when initializing
	// the XXfallback session, and is passed in via the remotePayload arg

	err := s.processRemoteHandshakePayload(remotePayload)
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

func (s *secureSession) runXXfallbackAsResponder(ctx context.Context, payload []byte) error {
	// stage 0 of regular XX flow is skipped in XXfallback for responder,
	// as the state is initialized from an earlier stage 0 IK message

	// stage 1 //
	err := s.sendHandshakeMessage(payload)
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

func (s *secureSession) runXXfallback(ctx context.Context, payload []byte, initialMsg []byte, ephemeral *core.Keypair) (err error) {
	// new XXfallback noise session
	ns, remotePayload, err := core.XXfallbackInitSession(s.initiator, s.prologue, *s.noiseKeypair, [32]byte{}, initialMsg, ephemeral)
	if err != nil {
		return err
	}
	s.ns = ns

	if s.initiator {
		return s.runXXfallbackAsInitiator(ctx, payload, remotePayload)
	}
	return s.runXXfallbackAsResponder(ctx, payload)
}
