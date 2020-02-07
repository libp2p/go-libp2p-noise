package noise

import (
	"context"
	"fmt"
	"github.com/gogo/protobuf/proto"
	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-noise/core"
	"github.com/libp2p/go-libp2p-noise/pb"
)

func (s *secureSession) verifyPayload(payload *pb.NoiseHandshakePayload, noiseKey [32]byte) (err error) {
	sig := payload.GetIdentitySig()
	msg := append([]byte(payloadSigningPrefix), noiseKey[:]...)

	ok, err := s.RemotePublicKey().Verify(msg, sig)
	if err != nil {
		return err
	} else if !ok {
		return fmt.Errorf("did not verify payload")
	}

	return nil
}

func (s *secureSession) setRemotePeerInfo(key []byte) (err error) {
	s.remote.libp2pKey, err = crypto.UnmarshalPublicKey(key)
	return err
}

func (s *secureSession) setRemotePeerID(key crypto.PubKey) (err error) {
	s.remotePeer, err = peer.IDFromPublicKey(key)
	return err
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
		return fmt.Errorf("error verifying handshake payload: %s", err)
	}
	return nil
}

func (s *secureSession) makeHandshakePayload() ([]byte, error) {
	// setup libp2p keys
	identityKeyBytes, err := crypto.MarshalPublicKey(s.LocalPublicKey())
	if err != nil {
		return nil, fmt.Errorf("error marshaling libp2p identity key: %s", err)
	}

	// sign noise data for payload
	noisePub := s.noiseKeypair.PubKey()
	sig, err := s.localKey.Sign(append([]byte(payloadSigningPrefix), noisePub[:]...))
	if err != nil {
		return nil, fmt.Errorf("error signing handshake payload: %s", err)
	}

	// create payload
	payload := new(pb.NoiseHandshakePayload)
	payload.IdentityKey = identityKeyBytes
	payload.IdentitySig = sig
	payloadEnc, err := proto.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("error marshaling handshake payload: %s", err)
	}
	return payloadEnc, nil
}

func (s *secureSession) runHandshake(ctx context.Context) error {
	payloadEnc, err := s.makeHandshakePayload()
	if err != nil {
		return fmt.Errorf("error creating noise handshake payload: %s", err)
	}

	// If we support Noise pipes, we try IK first, falling back to XX if IK fails.
	// The exception is when we're the initiator and don't know the other party's
	// static Noise key. Then IK will always fail, so we go straight to XX.
	tryIK := s.noisePipesSupport
	if s.initiator && s.noiseStaticKeyCache.Load(s.remotePeer) == [32]byte{} {
		tryIK = false
	}
	if tryIK {
		// we're either a responder or an initiator with a known static key for the remote peer, try IK
		buf, err := s.runIK(ctx, payloadEnc)
		if err == nil {
			s.ik_complete = true
			return nil
		}

		log.Debugf("IK handshake failed, trying XXfallback. IK err: %s", err)
		// IK failed, pipe to XXfallback
		err = s.runXXfallback(ctx, payloadEnc, buf)
		if err != nil {
			return err
		}
		s.xx_complete = true
		return nil
	}

	// If we don't support Noise pipes, or don't have a cached static key, run normal XX
	err = s.runXX(ctx, payloadEnc)
	if err != nil {
		return err
	}

	s.xx_complete = true
	return nil
}

type msgDecoder func([]byte) (*core.MessageBuffer, error)
type msgReceiver func(session *core.NoiseSession, buffer *core.MessageBuffer) (*core.NoiseSession, []byte, bool)
type msgEncoder func(buffer *core.MessageBuffer) []byte
type msgSender func(session *core.NoiseSession, payload []byte, ephemeral *core.Keypair) (*core.NoiseSession, core.MessageBuffer)

func (s *secureSession) recvHandshakeMessage(decoder msgDecoder, receiver msgReceiver) (encrypted []byte, plaintext []byte, err error) {
	buf, err := s.readMsgInsecure()
	if err != nil {
		return buf, nil, err
	}

	var msgbuf *core.MessageBuffer
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
	var msgbuf core.MessageBuffer
	s.ns, msgbuf = sender(s.ns, payload, nil)
	encMsgBuf := encoder(&msgbuf)

	return s.writeMsgInsecure(encMsgBuf)
}
