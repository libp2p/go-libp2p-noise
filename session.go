package noise

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/flynn/noise"
	logging "github.com/ipfs/go-log"

	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/peer"
)

var log = logging.Logger("noise")

var errNoKeypair = errors.New("cannot initiate secureSession - transport has no noise keypair")

type secureSession struct {
	insecure net.Conn

	initiator bool
	prologue  []byte

	localKey   crypto.PrivKey
	localPeer  peer.ID
	remotePeer peer.ID

	local  peerInfo
	remote peerInfo

	hs  *noise.HandshakeState
	enc *noise.CipherState
	dec *noise.CipherState

	handshakeComplete bool
	noiseKeypair      *Keypair

	msgBuffer []byte
	readLock  sync.Mutex
	writeLock sync.Mutex
}

type peerInfo struct {
	noiseKey  []byte // static noise public key
	libp2pKey crypto.PubKey
}

// newSecureSession creates a noise session over the given insecure Conn, using the static
// Noise keypair and libp2p identity keypair from the given Transport.
func newSecureSession(tpt *Transport, ctx context.Context, insecure net.Conn, remote peer.ID, initiator bool) (*secureSession, error) {
	if tpt.noiseKeypair == nil {
		return nil, errNoKeypair
	}

	localPeerInfo := peerInfo{
		noiseKey:  tpt.noiseKeypair.publicKey[:],
		libp2pKey: tpt.privateKey.GetPublic(),
	}

	s := &secureSession{
		insecure:     insecure,
		initiator:    initiator,
		prologue:     []byte{},
		localKey:     tpt.privateKey,
		localPeer:    tpt.localID,
		remotePeer:   remote,
		local:        localPeerInfo,
		msgBuffer:    []byte{},
		noiseKeypair: tpt.noiseKeypair,
	}

	err := s.runHandshake(ctx)
	if err != nil {
		_ = s.insecure.Close()
	}
	return s, err
}

func (s *secureSession) NoisePublicKey() [32]byte {
	return s.noiseKeypair.publicKey
}

func (s *secureSession) NoisePrivateKey() [32]byte {
	return s.noiseKeypair.privateKey
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

func (s *secureSession) Close() error {
	return s.insecure.Close()
}
