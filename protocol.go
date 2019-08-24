package noise

import (
	"context"
	"encoding/binary"
	"fmt"
	//"io"
	"net"
	"time"

	log "github.com/ChainSafe/log15"
	//proto "github.com/gogo/protobuf/proto"
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

	xx_complete bool
	ik_complete bool

	noisePipesSupport   bool
	noiseStaticKeyCache map[peer.ID]([32]byte)

	noisePrivateKey [32]byte
}

type peerInfo struct {
	noiseKey  [32]byte // static noise key
	libp2pKey crypto.PubKey
}

func newSecureSession(ctx context.Context, local peer.ID, privKey crypto.PrivKey, noisePrivateKey [32]byte,
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
		noisePrivateKey:     noisePrivateKey,
	}

	err := s.runHandshake(ctx)

	return s, err
}

func (s *secureSession) NoiseStaticKeyCache() map[peer.ID]([32]byte) {
	return s.noiseStaticKeyCache
}

func (s *secureSession) NoisePrivateKey() [32]byte {
	return s.noisePrivateKey
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

func (s *secureSession) runHandshake(ctx context.Context) error {

	log.Debug("runHandshake", "cache", s.noiseStaticKeyCache)

	// if we have the peer's noise static key and we support noise pipes, we can try IK
	if s.noiseStaticKeyCache[s.remotePeer] != [32]byte{} || s.noisePipesSupport {
		log.Debug("runHandshake_ik")

		// known static key for peer, try IK  //

		buf, err := s.runHandshake_ik(ctx)
		if err != nil {
			log.Error("runHandshake_ik", "err", err)

			// TODO: PIPE TO XX

			err = s.runHandshake_xx(ctx, true, buf)
			if err != nil {
				log.Error("runHandshake_xx", "err", err)
				return fmt.Errorf("runHandshake_xx err %s", err)
			}

			s.xx_complete = true
		}

		s.ik_complete = true

	} else {

		// unknown static key for peer, try XX //

		err := s.runHandshake_xx(ctx, false, nil)
		if err != nil {
			log.Error("runHandshake_xx", "err", err)
			return err
		}

		s.xx_complete = true
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

func (s *secureSession) Read(buf []byte) (int, error) {
	// TODO: use noise symmetric keys
	return s.insecure.Read(buf)

	plaintext, err := s.ReadSecure()
	if err != nil {
		return 0, nil
	}

	copy(buf, plaintext)
	return len(buf), nil
}

func (s *secureSession) ReadSecure() ([]byte, error) {
	l, err := s.ReadLength()
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, l)
	_, err = s.Read(ciphertext)
	if err != nil {
		return nil, err
	}

	return s.Decrypt(ciphertext)
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

	err := s.WriteSecure(in)
	return len(in), err
}

func (s *secureSession) WriteSecure(in []byte) error {
	ciphertext, err := s.Encrypt(in)
	if err != nil {
		return err
	}

	err = s.WriteLength(len(ciphertext))
	if err != nil {
		return err
	}

	_, err = s.Write(ciphertext)
	return err
}

func (s *secureSession) Close() error {
	return s.insecure.Close()
}
