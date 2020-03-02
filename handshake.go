package noise

import (
	"context"
	"fmt"
	"github.com/gogo/protobuf/proto"
	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/peer"

	"github.com/libp2p/go-libp2p-noise/pb"
	"github.com/libp2p/go-libp2p-noise/xx"
)

// payloadSigPrefix is prepended to our Noise static key before signing with
// our libp2p identity key.
const payloadSigPrefix = "noise-libp2p-static-key:"

func (s *secureSession) setRemotePeerInfo(key []byte) (err error) {
	s.remote.libp2pKey, err = crypto.UnmarshalPublicKey(key)
	return err
}

func (s *secureSession) setRemotePeerID(key crypto.PubKey) (err error) {
	s.remotePeer, err = peer.IDFromPublicKey(key)
	return err
}

func (s *secureSession) verifyPayload(payload *pb.NoiseHandshakePayload, noiseKey [32]byte) (err error) {
	sig := payload.GetIdentitySig()
	msg := append([]byte(payloadSigPrefix), noiseKey[:]...)

	ok, err := s.RemotePublicKey().Verify(msg, sig)
	if err != nil {
		return err
	} else if !ok {
		return fmt.Errorf("did not verify payload")
	}

	return nil
}

func (s *secureSession) sendHandshakeMessage(payload []byte, initialStage bool) error {
	var msgbuf xx.MessageBuffer
	s.ns, msgbuf = xx.SendMessage(s.ns, payload)
	var encMsgBuf []byte
	if initialStage {
		encMsgBuf = msgbuf.Encode0()
	} else {
		encMsgBuf = msgbuf.Encode1()
	}

	err := s.writeMsgInsecure(encMsgBuf)
	if err != nil {
		return fmt.Errorf("sendHandshakeMessage write to conn err=%s", err)
	}

	return nil
}

func (s *secureSession) recvHandshakeMessage(initialStage bool) (buf []byte, plaintext []byte, valid bool, err error) {
	buf, err = s.readMsgInsecure()
	if err != nil {
		return nil, nil, false, fmt.Errorf("recvHandshakeMessage read length err=%s", err)
	}

	var msgbuf *xx.MessageBuffer
	if initialStage {
		msgbuf, err = xx.Decode0(buf)
	} else {
		msgbuf, err = xx.Decode1(buf)
	}

	if err != nil {
		return buf, nil, false, fmt.Errorf("recvHandshakeMessage decode msg err=%s", err)
	}

	s.ns, plaintext, valid = xx.RecvMessage(s.ns, msgbuf)
	if !valid {
		return buf, nil, false, fmt.Errorf("recvHandshakeMessage validation fail")
	}

	return buf, plaintext, valid, nil
}

// Runs the XX handshake
// XX:
//   -> e
//   <- e, ee, s, es
//   -> s, se
func (s *secureSession) runHandshake(ctx context.Context) (err error) {

	// setup libp2p keys
	localKeyRaw, err := s.LocalPublicKey().Bytes()
	if err != nil {
		return fmt.Errorf("runHandshake err getting raw pubkey: %s", err)
	}

	// sign noise data for payload
	noise_pub := s.noiseKeypair.publicKey
	signedPayload, err := s.localKey.Sign(append([]byte(payloadSigPrefix), noise_pub[:]...))
	if err != nil {
		return fmt.Errorf("runHandshake signing payload err=%s", err)
	}

	// create payload
	payload := new(pb.NoiseHandshakePayload)
	payload.IdentityKey = localKeyRaw
	payload.IdentitySig = signedPayload
	payloadEnc, err := proto.Marshal(payload)
	if err != nil {
		return fmt.Errorf("runHandshake proto marshal payload err=%s", err)
	}

	kp := xx.NewKeypair(s.noiseKeypair.publicKey, s.noiseKeypair.privateKey)

	// new XX noise session
	s.ns = xx.InitSession(s.initiator, s.prologue, kp, [32]byte{})

	if s.initiator {
		// stage 0 //

		err = s.sendHandshakeMessage(nil, true)
		if err != nil {
			return fmt.Errorf("runHandshake stage 0 initiator fail: %s", err)
		}

		// stage 1 //

		var plaintext []byte
		var valid bool
		// read reply
		_, plaintext, valid, err = s.recvHandshakeMessage(false)
		if err != nil {
			return fmt.Errorf("runHandshake initiator stage 1 fail: %s", err)
		}
		if !valid {
			return fmt.Errorf("runHandshake stage 1 initiator validation fail")
		}

		// stage 2 //

		err = s.sendHandshakeMessage(payloadEnc, false)
		if err != nil {
			return fmt.Errorf("runHandshake stage=2 initiator=true err=%s", err)
		}

		// unmarshal payload
		nhp := new(pb.NoiseHandshakePayload)
		err = proto.Unmarshal(plaintext, nhp)
		if err != nil {
			return fmt.Errorf("runHandshake stage=2 initiator=true err=cannot unmarshal payload")
		}

		// set remote libp2p public key
		err = s.setRemotePeerInfo(nhp.GetIdentityKey())
		if err != nil {
			return fmt.Errorf("runHandshake stage=2 initiator=true read remote libp2p key fail")
		}

		// assert that remote peer ID matches libp2p public key
		pid, err := peer.IDFromPublicKey(s.RemotePublicKey())
		if pid != s.remotePeer {
			return fmt.Errorf("runHandshake stage=2 initiator=true check remote peer id err: expected %x got %x", s.remotePeer, pid)
		} else if err != nil {
			return fmt.Errorf("runHandshake stage 2 initiator check remote peer id err %s", err)
		}

		// verify payload is signed by libp2p key
		err = s.verifyPayload(nhp, s.ns.RemoteKey())
		if err != nil {
			return fmt.Errorf("runHandshake stage=2 initiator=true verify payload err=%s", err)
		}

	} else {

		// stage 0 //

		var plaintext []byte
		var valid bool
		nhp := new(pb.NoiseHandshakePayload)

		// read message
		_, plaintext, valid, err = s.recvHandshakeMessage(true)
		if err != nil {
			return fmt.Errorf("runHandshake stage=0 initiator=false err=%s", err)
		}

		if !valid {
			return fmt.Errorf("runHandshake stage=0 initiator=false err=validation fail")
		}

		// stage 1 //

		err = s.sendHandshakeMessage(payloadEnc, false)
		if err != nil {
			return fmt.Errorf("runHandshake stage=1 initiator=false err=%s", err)
		}

		// stage 2 //

		// read message
		_, plaintext, valid, err = s.recvHandshakeMessage(false)
		if err != nil {
			return fmt.Errorf("runHandshake stage=2 initiator=false err=%s", err)
		}

		if !valid {
			return fmt.Errorf("runHandshake stage=2 initiator=false err=validation fail")
		}

		// unmarshal payload
		err = proto.Unmarshal(plaintext, nhp)
		if err != nil {
			return fmt.Errorf("runHandshake stage=2 initiator=false err=cannot unmarshal payload")
		}

		// set remote libp2p public key
		err = s.setRemotePeerInfo(nhp.GetIdentityKey())
		if err != nil {
			return fmt.Errorf("runHandshake stage=2 initiator=false read remote libp2p key fail")
		}

		// set remote libp2p public key from payload
		err = s.setRemotePeerID(s.RemotePublicKey())
		if err != nil {
			return fmt.Errorf("runHandshake stage=2 initiator=false set remote peer id err=%s", err)
		}

		s.remote.noiseKey = s.ns.RemoteKey()

		// verify payload is signed by libp2p key
		err = s.verifyPayload(nhp, s.remote.noiseKey)
		if err != nil {
			return fmt.Errorf("runHandshake stage=2 initiator=false err=%s", err)
		}
	}

	s.handshakeComplete = true
	return nil
}
