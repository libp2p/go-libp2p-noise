package noise

import (
	"context"
	"fmt"
	"io"

	"github.com/gogo/protobuf/proto"
	"github.com/libp2p/go-libp2p-core/peer"

	"github.com/libp2p/go-libp2p-noise/handshake"
	"github.com/libp2p/go-libp2p-noise/pb"
)

func (s *secureSession) xx_sendHandshakeMessage(payload []byte, initial_stage bool) error {
	var msgbuf handshake.MessageBuffer
	s.ns, msgbuf = handshake.XXSendMessage(s.ns, payload, nil)
	var encMsgBuf []byte
	if initial_stage {
		encMsgBuf = msgbuf.XXEncode0()
	} else {
		encMsgBuf = msgbuf.XXEncode1()
	}

	err := s.writeLength(len(encMsgBuf))
	if err != nil {
		return fmt.Errorf("xx_sendHandshakeMessage write length err=%s", err)
	}

	_, err = s.insecure.Write(encMsgBuf)
	if err != nil {
		return fmt.Errorf("xx_sendHandshakeMessage write to conn err=%s", err)
	}

	return nil
}

func (s *secureSession) xx_recvHandshakeMessage(initial_stage bool) (buf []byte, plaintext []byte, valid bool, err error) {
	l, err := s.readLength()
	if err != nil {
		return nil, nil, false, fmt.Errorf("xx_recvHandshakeMessage read length err=%s", err)
	}

	buf = make([]byte, l)

	_, err = io.ReadFull(s.insecure, buf)
	if err != nil {
		return buf, nil, false, fmt.Errorf("xx_recvHandshakeMessage read from conn err=%s", err)
	}

	var msgbuf *handshake.MessageBuffer
	if initial_stage {
		msgbuf, err = handshake.XXDecode0(buf)
	} else {
		msgbuf, err = handshake.XXDecode1(buf)
	}

	if err != nil {
		return buf, nil, false, fmt.Errorf("xx_recvHandshakeMessage decode msg err=%s", err)
	}

	s.ns, plaintext, valid = handshake.XXRecvMessage(s.ns, msgbuf)
	if !valid {
		return buf, nil, false, fmt.Errorf("xx_recvHandshakeMessage validation fail")
	}

	return buf, plaintext, valid, nil
}

func (s *secureSession) processRemoteHandshakePayload(plaintext []byte) error {
	// unmarshal payload
	nhp := new(pb.NoiseHandshakePayload)
	err := proto.Unmarshal(plaintext, nhp)
	if err != nil {
		return fmt.Errorf("error unmarshaling remote handshake payload: %s", err)
	}

	// set remote libp2p public key
	err = s.setRemotePeerInfo(nhp.GetIdentityKey())
	if err != nil {
		return fmt.Errorf("error processing remote identity key: %s", err)
	}
	s.remote.noiseKey = s.ns.RemoteKey()

	pid, err := peer.IDFromPublicKey(s.RemotePublicKey())
	if err != nil {
		return fmt.Errorf("error getting remote peer id: %s", err)
	}

	if s.initiator {
		if pid != s.remotePeer {
			return fmt.Errorf("remote peer id mismatch: expected %s got %s", s.remotePeer.Pretty(), pid.Pretty())
		}
	} else {
		err = s.setRemotePeerID(s.RemotePublicKey())
		if err != nil {
			return fmt.Errorf("error setting peer id from remote public key: %s", err)
		}
	}

	// verify payload is signed by libp2p key
	err = s.verifyPayload(nhp, s.ns.RemoteKey())
	if err != nil {
		return fmt.Errorf("runHandshake_xx stage=2 initiator=true verify payload err=%s", err)
	}
	return nil
}

func (s *secureSession) runXXAsInitiator(ctx context.Context, payload []byte) error {
	// stage 0
	err := s.xx_sendHandshakeMessage(nil, true)
	if err != nil {
		return fmt.Errorf("runHandshake_xx stage 0 initiator fail: %s", err)
	}

	// stage 1
	// read reply
	_, plaintext, valid, err := s.xx_recvHandshakeMessage(false)
	if err != nil {
		return fmt.Errorf("runHandshake_xx initiator stage 1 fail: %s", err)
	}

	if !valid {
		return fmt.Errorf("runHandshake_xx stage 1 initiator validation fail")
	}

	err = s.processRemoteHandshakePayload(plaintext)
	if err != nil {
		return fmt.Errorf("error processing remote handshake payload: %s", err)
	}

	// stage 2 //
	err = s.xx_sendHandshakeMessage(payload, false)
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
		return fmt.Errorf("runHandshake_xx decode msg fail: %s", err)
	}

	var plaintext []byte
	var valid bool
	s.ns, plaintext, valid = handshake.XXRecvMessage(s.ns, msgbuf)
	if !valid {
		return fmt.Errorf("runHandshake_xx validation fail")
	}

	err = s.processRemoteHandshakePayload(plaintext)
	if err != nil {
		return fmt.Errorf("error processing remote handshake payload: %s", err)
	}

	// stage 2 //
	err = s.xx_sendHandshakeMessage(payload, false)
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
	_, _, valid, err := s.xx_recvHandshakeMessage(true)
	if err != nil {
		return fmt.Errorf("runHandshake_xx stage=0 initiator=false err=%s", err)
	}
	if !valid {
		return fmt.Errorf("runHandshake_xx stage=0 initiator=false err=validation fail")
	}

	// stage 1 //
	err = s.xx_sendHandshakeMessage(payload, false)
	if err != nil {
		return fmt.Errorf("runHandshake_xx stage=1 initiator=false err=%s", err)
	}

	// stage 2 //
	// read message
	var plaintext []byte
	_, plaintext, valid, err = s.xx_recvHandshakeMessage(false)
	if err != nil {
		return fmt.Errorf("runHandshake_xx stage=2 initiator=false err=%s", err)
	}
	if !valid {
		return fmt.Errorf("runHandshake_xx stage=2 initiator=false err=validation fail")
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
	err = s.xx_sendHandshakeMessage(payload, false)
	if err != nil {
		return fmt.Errorf("runHandshake_xx stage=1 initiator=false err=%s", err)
	}

	// stage 2 //
	// read message
	var plaintext []byte
	_, plaintext, valid, err = s.xx_recvHandshakeMessage(false)
	if err != nil {
		return fmt.Errorf("runHandshake_xx stage=2 initiator=false err=%s", err)
	}
	if !valid {
		return fmt.Errorf("runHandshake_xx stage=2 initiator=false err=validation fail")
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
// if fallback = true, initialMsg is used as the message in stage 1 of the initiator and stage 0
// of the responder
func (s *secureSession) runHandshake_xx(ctx context.Context, fallback bool, payload []byte, initialMsg []byte) (err error) {
	kp := handshake.NewKeypair(s.noiseKeypair.publicKey, s.noiseKeypair.privateKey)

	// new XX noise session
	s.ns = handshake.XXInitSession(s.initiator, s.prologue, kp, [32]byte{})

	if s.initiator {
		if fallback {
			return s.runXXfallbackAsInitiator(ctx, payload, initialMsg)
		}
		return s.runXXAsInitiator(ctx, payload)
	}

	if fallback {
		return s.runXXfallbackAsResponder(ctx, payload, initialMsg)
	}
	return s.runXXAsResponder(ctx, payload)
}
