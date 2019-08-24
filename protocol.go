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

			// TODO: PIPE TO XX

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
