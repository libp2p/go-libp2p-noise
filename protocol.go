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

type secureSession struct {
	insecure net.Conn

	initiator bool
	prologue  []byte

	localKey   crypto.PrivKey
	localPeer  peer.ID
	remotePeer peer.ID

	local  peerInfo
	remote peerInfo
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

func (s *secureSession) runHandshake(ctx context.Context) error {

	// TODO: check if static key for peer exists
	// if so, do XX; otherwise do IK

	// PHASE 1: TRY XX

	// get remote static key
	remotePub := [32]byte{}
	remotePubRaw, err := s.RemotePublicKey().Raw()
	if err != nil {
		return fmt.Errorf("remote pubkey fail: %s", err)
	}
	copy(remotePub[:], remotePubRaw)

	// generate local static noise key
	kp := xx.GenerateKeypair()

	// new XX noise session
	ns := xx.InitSession(s.initiator, s.prologue, kp, remotePub)

	// send initial payload message
	if s.initiator {
		// create payload
		payload := new(pb.NoiseHandshakePayload)
		msg, err := proto.Marshal(payload)
		if err != nil {
			return fmt.Errorf("proto marshal payload fail: %s", err)
		}

		var msgbuf xx.MessageBuffer
		ns, msgbuf = xx.SendMessage(ns, msg)

		encMsgBuf := msgbuf.Encode0()
		if len(encMsgBuf) != 56 {
			return fmt.Errorf("enc msg buf: len does not equal 56")
		}

		_, err = s.insecure.Write(encMsgBuf)
		if err != nil {
			return fmt.Errorf("write to conn fail: %s", err)
		}

		// 	buf := make([]byte, 144)
		// 	_, err = s.insecure.Read(buf)
		// 	if err != nil {
		// 		return fmt.Errorf("read from conn fail: %s", err)
		// 	}

		// 	var plaintext []byte
		// 	var valid bool
		// 	ns, plaintext, valid = xx.RecvMessage(ns, )
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
