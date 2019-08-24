package noise

import (
	"context"
	"encoding/binary"
	"fmt"
	//"io"
	"net"
	"time"

	log "github.com/ChainSafe/log15"
	proto "github.com/gogo/protobuf/proto"
	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/peer"
	//"github.com/libp2p/go-libp2p-core/sec"

	ik "github.com/ChainSafe/go-libp2p-noise/ik"
	pb "github.com/ChainSafe/go-libp2p-noise/pb"
	xx "github.com/ChainSafe/go-libp2p-noise/xx"
)

const payload_string = "noise-libp2p-static-key:"

type secureSession struct {
	insecure net.Conn

	initiator bool
	prologue  []byte

	localKey   crypto.PrivKey
	localPeer  peer.ID
	remotePeer peer.ID

	local  peerInfo
	remote peerInfo

	xx_ns *xx.NoiseSession
	ik_ns *ik.NoiseSession

	noisePipesSupport   bool
	noiseStaticKeyCache map[peer.ID]([32]byte)
}

type peerInfo struct {
	noiseKey  [32]byte // static noise key
	libp2pKey crypto.PubKey
}

func newSecureSession(ctx context.Context, local peer.ID, privKey crypto.PrivKey,
	insecure net.Conn, remote peer.ID, noiseStaticKeyCache map[peer.ID]([32]byte),
	noisePipesSupport bool, initiator bool) (*secureSession, error) {

	if noiseStaticKeyCache == nil {
		noiseStaticKeyCache = make(map[peer.ID]([32]byte))
	}
	s := &secureSession{
		insecure:            insecure,
		initiator:           initiator,
		prologue:            []byte(ID),
		localKey:            privKey,
		localPeer:           local,
		remotePeer:          remote,
		noisePipesSupport:   noisePipesSupport,
		noiseStaticKeyCache: noiseStaticKeyCache,
	}

	err := s.runHandshake(ctx)

	return s, err
}

func (s *secureSession) NoiseStaticKeyCache() map[peer.ID]([32]byte) {
	return s.noiseStaticKeyCache
}

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

func (s *secureSession) ik_sendHandshakeMessage(payload []byte) error {
	log.Debug("ik_sendHandshakeMessage", "initiator", s.initiator, "payload", payload, "payload len", len(payload))

	// create send message w payload
	var msgbuf ik.MessageBuffer
	s.ik_ns, msgbuf = ik.SendMessage(s.ik_ns, payload)
	var encMsgBuf []byte
	//if initial_stage {
	encMsgBuf = msgbuf.Encode0()
	// } else {
	// 	encMsgBuf = msgbuf.Encode1()
	// }

	log.Debug("ik_sendHandshakeMessage", "initiator", s.initiator, "msgbuf", msgbuf)
	log.Debug("ik_sendHandshakeMessage", "initiator", s.initiator, "encMsgBuf", encMsgBuf, "ns_len", len(msgbuf.NS()), "enc_len", len(encMsgBuf))

	// send message
	_, err := s.insecure.Write(encMsgBuf)
	if err != nil {
		log.Error("ik_sendHandshakeMessage", "initiator", s.initiator, "error", err)
		return fmt.Errorf("write to conn fail: %s", err)
	}

	return nil
}

func (s *secureSession) ik_recvHandshakeMessage(buf []byte) (plaintext []byte, valid bool, err error) {
	_, err = s.insecure.Read(buf)
	if err != nil {
		return nil, false, fmt.Errorf("read from conn fail: %s", err)
	}

	var msgbuf *ik.MessageBuffer
	//if initial_stage {
	msgbuf, err = ik.Decode0(buf)
	// } else {
	// 	msgbuf, err = ik.Decode1(buf)
	// }

	log.Debug("ik_recvHandshakeMessage", "initiator", s.initiator, "msgbuf", msgbuf, "buf len", len(buf))

	if err != nil {
		log.Error("ik_recvHandshakeMessage decode", "initiator", s.initiator, "error", err)
		return nil, false, fmt.Errorf("decode msg fail: %s", err)
	}

	s.ik_ns, plaintext, valid = ik.RecvMessage(s.ik_ns, msgbuf)
	if !valid {
		log.Error("ik_recvHandshakeMessage", "initiator", s.initiator, "error", "validation fail")
		return nil, false, fmt.Errorf("validation fail")
	}

	log.Debug("recv handshake message", "initiator", s.initiator, "msgbuf", msgbuf, "payload len", len(plaintext))

	return plaintext, valid, nil
}

func (s *secureSession) setRemotePeerInfo(key []byte) (err error) {
	s.remote.libp2pKey, err = crypto.UnmarshalPublicKey(key)
	return err
}

func (s *secureSession) setRemotePeerID(key crypto.PubKey) (err error) {
	s.remotePeer, err = peer.IDFromPublicKey(key)
	return err
}

func (s *secureSession) verifyPayload(payload *pb.NoiseHandshakePayload, noiseKey [32]byte) (err error) {
	sig := payload.GetNoiseStaticKeySignature()
	msg := append([]byte(payload_string), noiseKey[:]...)

	ok, err := s.RemotePublicKey().Verify(msg, sig)
	if err != nil {
		return err
	} else if !ok {
		return fmt.Errorf("did not verify payload")
	}

	return nil
}

func (s *secureSession) ReadLength() (int, error) {
	buf := make([]byte, 2)
	_, err := s.insecure.Read(buf)
	return int(binary.BigEndian.Uint16(buf)), err
}

func (s *secureSession) WriteLength(length int) error {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, uint16(length))
	_, err := s.insecure.Write(buf)
	return err
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

func (s *secureSession) runHandshake_ik(ctx context.Context, handshakeData []byte) error {
	// generate local static noise key
	kp := ik.GenerateKeypair()

	log.Debug("ik handshake", "pubkey", kp.PubKey())

	// setup libp2p keys
	localKeyRaw, err := s.LocalPublicKey().Bytes()
	if err != nil {
		return fmt.Errorf("err getting raw pubkey: %s", err)
	}

	log.Debug("ik handshake", "local key", localKeyRaw, "len", len(localKeyRaw))

	// sign noise data for payload
	noise_pub := kp.PubKey()
	signedPayload, err := s.localKey.Sign(append([]byte(payload_string), noise_pub[:]...))
	if err != nil {
		return fmt.Errorf("err signing payload: %s", err)
	}

	// create payload
	payload := new(pb.NoiseHandshakePayload)
	payload.Libp2PKey = localKeyRaw
	payload.NoiseStaticKeySignature = signedPayload
	payloadEnc, err := proto.Marshal(payload)
	if err != nil {
		return fmt.Errorf("proto marshal payload fail: %s", err)
	}

	// new XX noise session
	s.ik_ns = ik.InitSession(s.initiator, s.prologue, kp, [32]byte{})

	if s.initiator {
		// stage 0 //
		err := s.ik_sendHandshakeMessage(payloadEnc)
		if err != nil {
			log.Error("stage 0 initiator verify payload", "err", err)
			return fmt.Errorf("stage 0 initiator fail: %s", err)
		}

		// stage 1 //

	} else {

		// stage 0 //

		var plaintext []byte
		var valid bool
		if handshakeData != nil {
			var msgbuf *ik.MessageBuffer
			msgbuf, err = ik.Decode0(handshakeData)

			log.Debug("ik_recvHandshakeMessage", "responder", s.initiator, "msgbuf", msgbuf, "buf len", len(handshakeData))

			if err != nil {
				return fmt.Errorf("stage 0 responder fail: %s", err)
			}

			s.ik_ns, plaintext, valid = ik.RecvMessage(s.ik_ns, msgbuf)
			log.Debug("recv handshake message", "responder", s.initiator, "msgbuf", msgbuf, "payload len", len(plaintext))
		} else {
			// read message
			buf := make([]byte, 32+len(payloadEnc))
			plaintext, valid, err = s.ik_recvHandshakeMessage(buf)
			if err != nil {
				return fmt.Errorf("stage 0 responder fail: %s", err)
			}

		}

		if !valid {
			return fmt.Errorf("stage 0 responder validation fail")
		}

		log.Debug("stage 0 responder", "plaintext", plaintext, "plaintext len", len(plaintext))

		// unmarshal payload
		nhp := new(pb.NoiseHandshakePayload)
		err = proto.Unmarshal(plaintext, nhp)
		if err != nil {
			return fmt.Errorf("stage 0 responder validation fail: cannot unmarshal payload")
		}

		// set remote libp2p public key
		err = s.setRemotePeerInfo(nhp.GetLibp2PKey())
		if err != nil {
			log.Error("stage 0 responder set remote peer info", "err", err)
			return fmt.Errorf("stage 0 responder read remote libp2p key fail")
		}

		// assert that remote peer ID matches libp2p key
		err = s.setRemotePeerID(s.RemotePublicKey())
		if err != nil {
			log.Error("stage 0 responder set remote peer id", "err", err)
		}

		// verify payload is signed by libp2p key
		err = s.verifyPayload(nhp, s.ik_ns.RemoteKey())
		if err != nil {
			log.Error("stage 1 responder verify payload", "err", err)
		}

	}

	return nil
}

func (s *secureSession) runHandshake(ctx context.Context) error {

	// TODO: check if static key for peer exists
	// if not, do XX; otherwise do IK

	log.Debug("runHandshake", "cache", s.noiseStaticKeyCache)

	// try
	if s.noiseStaticKeyCache[s.remotePeer] != [32]byte{} && s.noisePipesSupport {
		//if s.noisePipesSupport {
		log.Debug("runHandshake_ik")
		// ******************************************** //
		// known static key for peer, try IK  //
		// ******************************************** //

		err := s.runHandshake_ik(ctx, nil)
		if err != nil {
			log.Error("runHandshake_ik", "err", err)

			// PIPE TO XX
		}

	} else {
		// ******************************************** //
		// unknown static key for peer, try XX //
		// ******************************************** //

		// generate local static noise key
		kp := xx.GenerateKeypair()

		log.Debug("xx handshake", "pubkey", kp.PubKey())

		// setup libp2p keys
		localKeyRaw, err := s.LocalPublicKey().Bytes()
		if err != nil {
			return fmt.Errorf("err getting raw pubkey: %s", err)
		}

		log.Debug("xx handshake", "local key", localKeyRaw, "len", len(localKeyRaw))

		// sign noise data for payload
		noise_pub := kp.PubKey()
		signedPayload, err := s.localKey.Sign(append([]byte(payload_string), noise_pub[:]...))
		if err != nil {
			return fmt.Errorf("err signing payload: %s", err)
		}

		s.local.noiseKey = noise_pub

		// create payload
		payload := new(pb.NoiseHandshakePayload)
		payload.Libp2PKey = localKeyRaw
		payload.NoiseStaticKeySignature = signedPayload
		payloadEnc, err := proto.Marshal(payload)
		if err != nil {
			return fmt.Errorf("proto marshal payload fail: %s", err)
		}

		// new XX noise session
		s.xx_ns = xx.InitSession(s.initiator, s.prologue, kp, [32]byte{})

		handshakeData, err := s.runHandshake_xx(ctx, payloadEnc)
		if err != nil {
			log.Error("runHandshake_xx", "err", err)
			log.Debug("try runHandshake_ik...")
			err := s.runHandshake_ik(ctx, handshakeData)
			if err != nil {
				return fmt.Errorf("runHandshake_ik err %s", err)
			}
			//return fmt.Errorf("runHandshake_xx err %s", err)
		}
	}

	return nil
}

func (s *secureSession) LocalAddr() net.Addr {
	return s.insecure.LocalAddr()
}

func (s *secureSession) LocalPeer() peer.ID {
	return s.localPeer
}

func (s *secureSession) LocalPrivateKey() crypto.PrivKey {
	return s.localKey
}

func (s *secureSession) LocalPublicKey() crypto.PubKey {
	return s.localKey.GetPublic()
}

func (s *secureSession) Read(in []byte) (int, error) {
	// TODO: use noise symmetric keys
	return s.insecure.Read(in)
}

func (s *secureSession) RemoteAddr() net.Addr {
	return s.insecure.RemoteAddr()
}

func (s *secureSession) RemotePeer() peer.ID {
	return s.remotePeer
}

func (s *secureSession) RemotePublicKey() crypto.PubKey {
	return s.remote.libp2pKey
}

func (s *secureSession) SetDeadline(t time.Time) error {
	return s.insecure.SetDeadline(t)
}

func (s *secureSession) SetReadDeadline(t time.Time) error {
	return s.insecure.SetReadDeadline(t)
}

func (s *secureSession) SetWriteDeadline(t time.Time) error {
	return s.insecure.SetWriteDeadline(t)
}

func (s *secureSession) Write(in []byte) (int, error) {
	// TODO: use noise symmetric keys
	return s.insecure.Write(in)
}

func (s *secureSession) Close() error {
	return s.insecure.Close()
}
