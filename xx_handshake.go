package noise

import (
	"context"
	"fmt"
	log "github.com/ChainSafe/log15"
	proto "github.com/gogo/protobuf/proto"
	"github.com/libp2p/go-libp2p-core/peer"

	xx "github.com/ChainSafe/go-libp2p-noise/xx"
	pb "github.com/ChainSafe/go-libp2p-noise/pb"
)

func (s *secureSession) xx_sendHandshakeMessage(payload []byte, initial_stage bool) error {
	log.Debug("xx_sendHandshakeMessage", "initiator", s.initiator, "payload", payload, "payload len", len(payload), "initial_stage", initial_stage)

	// create send message w payload
	var msgbuf xx.MessageBuffer
	s.xx_ns, msgbuf = xx.SendMessage(s.xx_ns, payload)
	var encMsgBuf []byte
	if initial_stage {
		encMsgBuf = msgbuf.Encode0()
	} else {
		encMsgBuf = msgbuf.Encode1()
	}

	log.Debug("xx_sendHandshakeMessage", "initiator", s.initiator, "msgbuf", msgbuf, "initial_stage", initial_stage)
	log.Debug("xx_sendHandshakeMessage", "initiator", s.initiator, "encMsgBuf", encMsgBuf, "ns_len", len(msgbuf.NS()), "enc_len", len(encMsgBuf), "initial_stage", initial_stage)

	err := s.WriteLength(len(encMsgBuf))
	if err != nil {
		log.Error("xx_sendHandshakeMessage", "initiator", s.initiator, "error", err)
		return fmt.Errorf("xx_sendHandshakeMessage write length fail: %s", err)
	}

	// send message
	_, err = s.insecure.Write(encMsgBuf)
	if err != nil {
		log.Error("xx_sendHandshakeMessage", "initiator", s.initiator, "error", err)
		return fmt.Errorf("xx_sendHandshakeMessage write to conn fail: %s", err)
	}

	return nil
}

func (s *secureSession) xx_recvHandshakeMessage(initial_stage bool) (buf []byte, plaintext []byte, valid bool, err error) {
	l, err := s.ReadLength()
	if err != nil {
		return nil, nil, false, fmt.Errorf("read length fail: %s", err)
	}

	buf = make([]byte, l)

	_, err = s.insecure.Read(buf)
	if err != nil {
		return buf, nil, false, fmt.Errorf("read from conn fail: %s", err)
	}

	var msgbuf *xx.MessageBuffer
	if initial_stage {
		msgbuf, err = xx.Decode0(buf)
	} else {
		msgbuf, err = xx.Decode1(buf)
	}

	log.Debug("xx_recvHandshakeMessage", "initiator", s.initiator, "msgbuf", msgbuf, "buf len", len(buf), "initial_stage", initial_stage)

	if err != nil {
		log.Debug("xx_recvHandshakeMessage decode", "initiator", s.initiator, "error", err)
		return buf, nil, false, fmt.Errorf("decode msg fail: %s", err)
	}

	s.xx_ns, plaintext, valid = xx.RecvMessage(s.xx_ns, msgbuf)
	if !valid {
		log.Error("xx_recvHandshakeMessage", "initiator", s.initiator, "error", "validation fail")
		return buf, nil, false, fmt.Errorf("validation fail")
	}

	log.Debug("xx_recvHandshakeMessage", "initiator", s.initiator, "msgbuf", msgbuf, "payload len", len(plaintext))

	return buf, plaintext, valid, nil
}

func (s *secureSession) runHandshake_xx(ctx context.Context, payloadEnc []byte) (handshakeData []byte, err error) {
	if s.initiator {
		// stage 0 //

		err = s.xx_sendHandshakeMessage(payloadEnc, true)
		if err != nil {
			return nil, fmt.Errorf("stage 0 initiator fail: %s", err)
		}

		// stage 1 //

		// read reply
		buf, plaintext, valid, err := s.xx_recvHandshakeMessage(false)
		if err != nil {
			return buf, fmt.Errorf("initiator stage 1 fail: %s", err)
		}

		if !valid {
			return buf, fmt.Errorf("stage 1 initiator validation fail")
		}

		log.Debug("stage 1 initiator", "payload", plaintext)

		// unmarshal payload
		nhp := new(pb.NoiseHandshakePayload)
		err = proto.Unmarshal(plaintext, nhp)
		if err != nil {
			return buf, fmt.Errorf("stage 1 initiator validation fail: cannot unmarshal payload")
		}

		// set remote libp2p public key
		err = s.setRemotePeerInfo(nhp.GetLibp2PKey())
		if err != nil {
			log.Error("stage 1 initiator set remote peer info", "err", err)
			return buf, fmt.Errorf("stage 1 initiator read remote libp2p key fail")
		}

		// assert that remote peer ID matches libp2p public key
		pid, err := peer.IDFromPublicKey(s.RemotePublicKey())
		if pid != s.remotePeer {
			log.Error("stage 1 initiator check remote peer id err", "expected", s.remotePeer, "got", pid)
		} else if err != nil {
			log.Error("stage 1 initiator check remote peer id", "err", err)
		}

		// verify payload is signed by libp2p key
		err = s.verifyPayload(nhp, s.xx_ns.RemoteKey())
		if err != nil {
			log.Error("stage 1 initiator verify payload", "err", err)
		}

		s.noiseStaticKeyCache[s.remotePeer] = s.xx_ns.RemoteKey()
		log.Debug("stage 1 initiator", "remote key", s.xx_ns.RemoteKey())

		// stage 2 //

		err = s.xx_sendHandshakeMessage(s.local.noiseKey[:], false)
		if err != nil {
			return buf, fmt.Errorf("stage 2 intiator fail: %s", err)
		}

	} else {

		// stage 0 //

		// read message
		buf, plaintext, valid, err := s.xx_recvHandshakeMessage(true)
		if err != nil {
			return buf, fmt.Errorf("stage 0 responder fail: %s", err)
		}

		if !valid {
			return buf, fmt.Errorf("stage 0 responder validation fail")
		}

		log.Debug("stage 0 responder", "plaintext", plaintext, "plaintext len", len(plaintext))

		// unmarshal payload
		nhp := new(pb.NoiseHandshakePayload)
		err = proto.Unmarshal(plaintext, nhp)
		if err != nil {
			return buf, fmt.Errorf("stage 0 responder validation fail: cannot unmarshal payload")
		}

		// set remote libp2p public key
		err = s.setRemotePeerInfo(nhp.GetLibp2PKey())
		if err != nil {
			log.Error("stage 0 responder set remote peer info", "err", err)
			return buf, fmt.Errorf("stage 0 responder read remote libp2p key fail")
		}

		// assert that remote peer ID matches libp2p key
		err = s.setRemotePeerID(s.RemotePublicKey())
		if err != nil {
			log.Error("stage 0 responder set remote peer id", "err", err)
		}

		// stage 1 //

		err = s.xx_sendHandshakeMessage(payloadEnc, false)
		if err != nil {
			return buf, fmt.Errorf("stage 1 responder fail: %s", err)
		}

		// stage 2 //

		// read message
		buf, plaintext, valid, err = s.xx_recvHandshakeMessage(false)
		if err != nil {
			return buf, fmt.Errorf("stage 2 responder fail: %s", err)
		}

		if !valid {
			return buf, fmt.Errorf("stage 2 responder validation fail")
		}

		log.Debug("stage 2 responder", "plaintext", plaintext, "remote key", s.xx_ns.RemoteKey())

		copy(s.remote.noiseKey[:], plaintext)

		// verify payload is signed by libp2p key
		err = s.verifyPayload(nhp, s.remote.noiseKey)
		if err != nil {
			log.Error("stage 2 responder verify payload", "err", err)
			return buf, fmt.Errorf("stage 2 responder fail: %s", err)
		}

		s.noiseStaticKeyCache[s.remotePeer] = s.remote.noiseKey
		log.Debug("stage 2 responder", "remote key", s.remote.noiseKey)
	}

	return nil, nil
}