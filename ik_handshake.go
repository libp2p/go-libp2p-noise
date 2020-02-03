package noise

import (
	"context"
	"fmt"
	"github.com/libp2p/go-libp2p-core/peer"
	"io"

	proto "github.com/gogo/protobuf/proto"
	handshake "github.com/libp2p/go-libp2p-noise/handshake"
	pb "github.com/libp2p/go-libp2p-noise/pb"
)

func (s *secureSession) ik_sendHandshakeMessage(payload []byte, initial_stage bool) error {
	var msgbuf handshake.MessageBuffer
	s.ik_ns, msgbuf = handshake.IKSendMessage(s.ik_ns, payload)
	var encMsgBuf []byte
	if initial_stage {
		encMsgBuf = msgbuf.IKEncode0()
	} else {
		encMsgBuf = msgbuf.IKEncode1()
	}

	err := s.writeLength(len(encMsgBuf))
	if err != nil {
		return fmt.Errorf("ik_sendHandshakeMessage write length err=%s", err)
	}

	// send message
	_, err = s.insecure.Write(encMsgBuf)
	if err != nil {
		return fmt.Errorf("ik_sendHandshakeMessage write to conn err=%s", err)
	}

	return nil
}

func (s *secureSession) ik_recvHandshakeMessage(initial_stage bool) (buf []byte, plaintext []byte, valid bool, err error) {
	l, err := s.readLength()
	if err != nil {
		return nil, nil, false, fmt.Errorf("ik_recvHandshakeMessage read length err=%s", err)
	}

	buf = make([]byte, l)

	_, err = io.ReadFull(s.insecure, buf)
	if err != nil {
		return buf, nil, false, fmt.Errorf("ik_recvHandshakeMessage read from conn err=%s", err)
	}

	var msgbuf *handshake.MessageBuffer
	if initial_stage {
		msgbuf, err = handshake.IKDecode0(buf)
	} else {
		msgbuf, err = handshake.IKDecode1(buf)
	}

	if err != nil {
		return buf, nil, false, fmt.Errorf("ik_recvHandshakeMessage decode msg fail: %s", err)
	}

	s.ik_ns, plaintext, valid = handshake.IKRecvMessage(s.ik_ns, msgbuf)
	if !valid {
		return buf, nil, false, fmt.Errorf("ik_recvHandshakeMessage validation fail")
	}

	return buf, plaintext, valid, nil
}

// IK:
//     <- s
//     ...
//     -> e, es, s, ss
//     <- e, ee, se
// returns last successful message upon error
func (s *secureSession) runHandshake_ik(ctx context.Context, payload []byte) ([]byte, error) {
	kp := handshake.NewKeypair(s.noiseKeypair.publicKey, s.noiseKeypair.privateKey)

	remoteNoiseKey := s.noiseStaticKeyCache.Load(s.remotePeer)

	// new IK noise session
	s.ik_ns = handshake.IKInitSession(s.initiator, s.prologue, kp, remoteNoiseKey)

	if s.initiator {
		// bail out early if we don't know the remote Noise key
		if remoteNoiseKey == [32]byte{} {
			return nil, fmt.Errorf("runHandshake_ik aborting - unknown static key for peer %s", s.remotePeer.Pretty())
		}

		// stage 0 //
		err := s.ik_sendHandshakeMessage(payload, true)
		if err != nil {
			return nil, fmt.Errorf("runHandshake_ik stage=0 initiator=true err=%s", err)
		}

		// stage 1 //

		// read message
		buf, plaintext, valid, err := s.ik_recvHandshakeMessage(false)
		if err != nil {
			return buf, fmt.Errorf("runHandshake_ik stage=1 initiator=true err=%s", err)
		}

		if !valid {
			return buf, fmt.Errorf("runHandshake_ik stage=1 initiator=true err=validation fail")
		}

		// unmarshal payload
		nhp := new(pb.NoiseHandshakePayload)
		err = proto.Unmarshal(plaintext, nhp)
		if err != nil {
			return buf, fmt.Errorf("runHandshake_ik stage=1 initiator=true err=validation fail: cannot unmarshal payload")
		}

		// set remote libp2p public key
		err = s.setRemotePeerInfo(nhp.GetIdentityKey())
		if err != nil {
			return buf, fmt.Errorf("runHandshake_ik stage=1 initiator=true err=read remote libp2p key fail")
		}

		// assert that remote peer ID matches libp2p public key
		pid, err := peer.IDFromPublicKey(s.RemotePublicKey())
		if pid != s.remotePeer {
			return buf, fmt.Errorf("runHandshake_ik stage=1 initiator=true  check remote peer id err: expected %x got %x", s.remotePeer, pid)
		} else if err != nil {
			return buf, fmt.Errorf("runHandshake_ik stage=1 initiator=true  check remote peer id err %s", err)
		}

		// verify payload is signed by libp2p key
		err = s.verifyPayload(nhp, remoteNoiseKey)
		if err != nil {
			return buf, fmt.Errorf("runHandshake_ik stage=1 initiator=true verify payload err=%s", err)
		}

	} else {
		// stage 0 //

		// read message
		buf, plaintext, valid, err := s.ik_recvHandshakeMessage(true)
		if err != nil {
			return buf, fmt.Errorf("runHandshake_ik stage=0 initiator=false err=%s", err)
		}

		if !valid {
			return buf, fmt.Errorf("runHandshake_ik stage=0 initiator=false err: validation fail")
		}

		// unmarshal payload
		nhp := new(pb.NoiseHandshakePayload)
		err = proto.Unmarshal(plaintext, nhp)
		if err != nil {
			return buf, fmt.Errorf("runHandshake_ik stage=0 initiator=false err=validation fail: cannot unmarshal payload")
		}

		// set remote libp2p public key
		err = s.setRemotePeerInfo(nhp.GetIdentityKey())
		if err != nil {
			return buf, fmt.Errorf("runHandshake_ik stage=0 initiator=false err=read remote libp2p key fail")
		}

		// assert that remote peer ID matches libp2p key
		err = s.setRemotePeerID(s.RemotePublicKey())
		if err != nil {
			return buf, fmt.Errorf("runHandshake_ik stage=0 initiator=false set remote peer id err=%s:", err)
		}

		// verify payload is signed by libp2p key
		err = s.verifyPayload(nhp, s.ik_ns.RemoteKey())
		if err != nil {
			return buf, fmt.Errorf("runHandshake_ik stage=0 initiator=false verify payload err=%s", err)
		}

		// stage 1 //

		err = s.ik_sendHandshakeMessage(payload, false)
		if err != nil {
			return nil, fmt.Errorf("runHandshake_ik stage=1 initiator=false send err=%s", err)
		}

	}
	return nil, nil
}
