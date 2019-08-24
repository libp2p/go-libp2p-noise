package noise

import (
	"context"
	"fmt"
	//"io"
	"net"
	"time"

	log "github.com/ChainSafe/log15"
	proto "github.com/gogo/protobuf/proto"
	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/sec"

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

	ns *xx.NoiseSession
}

// TODO:  after reading payloads in initial message, fill in the peerInfo
type peerInfo struct {
	noiseKey  crypto.PubKey // static noise key
	libp2pKey crypto.PubKey
}

func newSecureSession(ctx context.Context, local peer.ID, privKey crypto.PrivKey, insecure net.Conn, remote peer.ID, initiator bool) (sec.SecureConn, error) {
	s := &secureSession{
		insecure:   insecure,
		initiator:  initiator,
		prologue:   []byte(ID),
		localKey:   privKey,
		localPeer:  local,
		remotePeer: remote,
	}

	err := s.runHandshake(ctx)

	return s, err
}

func (s *secureSession) sendHandshakeMessage(payload []byte, initial_stage bool) error {
	log.Debug("send handshake message", "initiator", s.initiator, "payload", payload, "payload len", len(payload), "initial_stage", initial_stage)

	// create send message w payload
	var msgbuf xx.MessageBuffer
	s.ns, msgbuf = xx.SendMessage(s.ns, payload)
	var encMsgBuf []byte
	if initial_stage {
		encMsgBuf = msgbuf.Encode0()
	} else {
		encMsgBuf = msgbuf.Encode1()
	}

	log.Debug("send handshake message", "intiator", s.initiator, "msgbuf", msgbuf, "initial_stage", initial_stage)
	log.Debug("send handshake message", "intiator", s.initiator, "encMsgBuf", encMsgBuf, "ns_len", len(msgbuf.NS()), "enc_len", len(encMsgBuf), "initial_stage", initial_stage)

	// send message
	_, err := s.insecure.Write(encMsgBuf)
	if err != nil {
		log.Debug("send handshake message", "initiator", s.initiator, "error", err)
		return fmt.Errorf("write to conn fail: %s", err)
	}

	return nil
}

func (s *secureSession) recvHandshakeMessage(buf []byte, initial_stage bool) (plaintext []byte, valid bool, err error) {
	_, err = s.insecure.Read(buf)
	if err != nil {
		return nil, false, fmt.Errorf("read from conn fail: %s", err)
	}

	var msgbuf *xx.MessageBuffer
	if initial_stage {
		msgbuf, err = xx.Decode0(buf)
	} else {
		msgbuf, err = xx.Decode1(buf)
	}

	log.Debug("recv handshake message", "initiator", s.initiator, "msgbuf", msgbuf, "buf len", len(buf), "initial_stage", initial_stage)

	if err != nil {
		log.Debug("recv handshake message decode", "initiator", s.initiator, "error", err)
		return nil, false, fmt.Errorf("decode msg fail: %s", err)
	}

	s.ns, plaintext, valid = xx.RecvMessage(s.ns, msgbuf)
	if !valid {
		log.Debug("recv handshake message xx", "initiator", s.initiator, "error", "validation fail")
		return nil, false, fmt.Errorf("validation fail")
	}

	log.Debug("recv handshake message", "initiator", s.initiator, "msgbuf", msgbuf, "payload len", len(plaintext))

	return plaintext, valid, nil
}

func (s *secureSession) setRemotePeerInfo(key []byte) (err error) {
	s.remote.libp2pKey, err = crypto.UnmarshalEd25519PublicKey(key)
	return err
}

func (s *secureSession) runHandshake(ctx context.Context) error {

	// s.remote = remotePeerInfo

	// TODO: check if static key for peer exists
	// if so, do XX; otherwise do IK

	// ******************************************** //
	// ************** PHASE 1: TRY XX ************* //
	// ******************************************** //

	// get remote static key
	// remotePub := [32]byte{}
	// remotePubRaw, err := s.RemotePublicKey().Raw()
	// if err != nil {
	// 	return fmt.Errorf("remote pubkey fail: %s", err)
	// }
	// copy(remotePub[:], remotePubRaw)

	// generate local static noise key
	kp := xx.GenerateKeypair()

	log.Debug("xx handshake", "pubkey", kp.PubKey())

	// setup libp2p keys
	localKeyRaw, err := s.LocalPublicKey().Raw()
	if err != nil {
		return fmt.Errorf("err getting raw pubkey: %s", err)
	}

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
	s.ns = xx.InitSession(s.initiator, s.prologue, kp, [32]byte{})

	if s.initiator {
		// stage 0 //

		err = s.sendHandshakeMessage(payloadEnc, true)
		if err != nil {
			return fmt.Errorf("stage 0 intiator fail: %s", err)
		}

		// stage 1 //

		// read reply
		buf := make([]byte, 96+(2*len(payloadEnc)))
		plaintext, valid, err := s.recvHandshakeMessage(buf, false)
		if err != nil {
			return fmt.Errorf("intiator stage 1 fail: %s", err)
		}

		if !valid {
			return fmt.Errorf("stage 1 initiator validation fail")
		}

		// TODO: check payload
		log.Debug("stage 1 initiator", "payload", plaintext)

		nsp := new(pb.NoiseHandshakePayload)
		err = proto.Unmarshal(plaintext, nsp)
		if err != nil {
			return fmt.Errorf("stage 1 initiator validation fail: cannot unmarshal payload")
		}

		log.Debug("stage 1 initiator", "libp2pkey", fmt.Sprintf("%x", nsp.GetLibp2PKey()))

		err = s.setRemotePeerInfo(nsp.GetLibp2PKey())
		if err != nil {
			return fmt.Errorf("stage 1 initiator read remote libp2p key fail")
		}

		// stage 2 //

		err = s.sendHandshakeMessage(append(plaintext, payloadEnc...), false)
		if err != nil {
			return fmt.Errorf("stage 2 intiator fail: %s", err)
		}

	} else {

		// stage 0 //

		// read message
		buf := make([]byte, 32+len(payloadEnc))
		plaintext, valid, err := s.recvHandshakeMessage(buf, true)
		if err != nil {
			return fmt.Errorf("stage 0 responder fail: %s", err)
		}

		if !valid {
			return fmt.Errorf("stage 0 responder validation fail")
		}

		// TODO: check payload
		log.Debug("stage 0 responder", "plaintext", plaintext, "plaintext len", len(plaintext))

		err = s.setRemotePeerInfo(plaintext[:32])
		if err != nil {
			return fmt.Errorf("stage 0 responder read remote libp2p key fail")
		}

		// stage 1 //

		err = s.sendHandshakeMessage(append(plaintext, payloadEnc...), false)
		if err != nil {
			return fmt.Errorf("stage 1 responder fail: %s", err)
		}

		// stage 2 //

		// read message
		buf = make([]byte, 96+(3*len(payloadEnc)))
		plaintext, valid, err = s.recvHandshakeMessage(buf, false)
		if err != nil {
			return fmt.Errorf("stage 2 responder fail: %s", err)
		}

		if !valid {
			return fmt.Errorf("stage 2 responder validation fail")
		}

		// TODO: check payload
		log.Debug("stage 2 responder", "payload", plaintext)
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
	return s.insecure.Write(in)
}

func (s *secureSession) Close() error {
	return s.insecure.Close()
}
