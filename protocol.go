package noise

import (
	"context"
	"fmt"
	"net"
	"time"

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

func newSecureSession(ctx context.Context, local peer.ID, privKey crypto.PrivKey, insecure net.Conn, remote peer.ID, initiator bool) (sec.SecureConn, error) {

	s := &secureSession{
		insecure:   insecure,
		initiator:  initiator,
		prologue:   []byte(ID),
		localKey:   privKey,
		localPeer:  local,
		remotePeer: remote,
	}

	return s, nil
}

func (s *secureSession) sendHandshakeMessage(payload []byte, initial_stage bool) error {
	// create send message w payload
	var msgbuf xx.MessageBuffer
	s.ns, msgbuf = xx.SendMessage(s.ns, payload)
	var encMsgBuf []byte
	if initial_stage {
		encMsgBuf = msgbuf.Encode0()
	} else {
		encMsgBuf = msgbuf.Encode1()
	}

	// send message
	_, err := s.insecure.Write(encMsgBuf)
	if err != nil {
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

	if err != nil {
		return nil, false, fmt.Errorf("decode msg fail: %s", err)
	}

	s.ns, plaintext, valid = xx.RecvMessage(s.ns, msgbuf)
	if !valid {
		return nil, false, fmt.Errorf("validation fail")
	}

	return plaintext, valid, nil
}

func (s *secureSession) runHandshake(ctx context.Context) error {

	// TODO: check if static key for peer exists
	// if so, do XX; otherwise do IK

	// ******************************************** //
	// ************** PHASE 1: TRY XX ************* //
	// ******************************************** //

	// get remote static key
	remotePub := [32]byte{}
	remotePubRaw, err := s.RemotePublicKey().Raw()
	if err != nil {
		return fmt.Errorf("remote pubkey fail: %s", err)
	}
	copy(remotePub[:], remotePubRaw)

	// generate local static noise key
	kp := xx.GenerateKeypair()

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
	s.ns = xx.InitSession(s.initiator, s.prologue, kp, remotePub)

	if s.initiator {
		// stage 0 //

		err = s.sendHandshakeMessage(payloadEnc, true)
		if err != nil {
			return fmt.Errorf("stage 0 intiator fail: %s", err)
		}

		// stage 1 //

		// read reply
		buf := make([]byte, 80+(2*len(payloadEnc)))
		plaintext, valid, err := s.recvHandshakeMessage(buf, false)
		if err != nil {
			return fmt.Errorf("intiator stage 1 fail: %s", err)
		}

		if !valid {
			return fmt.Errorf("stage 1 initiator validation fail")
		}

		// TODO: check payload
		fmt.Printf("%x", plaintext)

		// stage 2 //

		err = s.sendHandshakeMessage(nil, false)
		if err != nil {
			return fmt.Errorf("stage 2 intiator fail: %s", err)
		}

	} else {

		// stage 0 //

		// read message
		buf := make([]byte, 32+len(payloadEnc))
		plaintext, valid, err := s.recvHandshakeMessage(buf, false)
		if err != nil {
			return fmt.Errorf("stage 0 responder fail: %s", err)
		}

		if !valid {
			return fmt.Errorf("stage 0 responder validation fail")
		}

		// TODO: check payload
		fmt.Printf("%x", plaintext)

		// stage 1 //

		err = s.sendHandshakeMessage(payloadEnc, true)
		if err != nil {
			return fmt.Errorf("stage 1 responder fail: %s", err)
		}

		// stage 2 //

		// read message
		buf = make([]byte, 80+(3*len(payloadEnc)))
		plaintext, valid, err = s.recvHandshakeMessage(buf, false)
		if err != nil {
			return fmt.Errorf("stage 2 responder fail: %s", err)
		}

		if !valid {
			return fmt.Errorf("stage 2 responder validation fail")
		}

		// TODO: check payload
		fmt.Printf("%x", plaintext)
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
	return s.remote.staticKey
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
