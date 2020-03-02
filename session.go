package noise

import (
	"context"
	"crypto/rand"
	"net"
	"sync"
	"time"

	"github.com/flynn/noise"
	logging "github.com/ipfs/go-log"

	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/peer"
)

var log = logging.Logger("noise")

type noiseState struct {
	initiator   bool
	localStatic noise.DHKey

	hs  *noise.HandshakeState
	enc *noise.CipherState
	dec *noise.CipherState
}

type secureSession struct {
	ns noiseState

	localID   peer.ID
	localKey  crypto.PrivKey
	remoteID  peer.ID
	remoteKey crypto.PubKey

	insecure  net.Conn
	msgBuffer []byte
	readLock  sync.Mutex
	writeLock sync.Mutex
}

// newSecureSession creates a noise session over the given insecure Conn, using the
// libp2p identity keypair from the given Transport.
func newSecureSession(tpt *Transport, ctx context.Context, insecure net.Conn, remote peer.ID, initiator bool) (*secureSession, error) {
	kp, err := noise.DH25519.GenerateKeypair(rand.Reader)
	if err != nil {
		return nil, err
	}

	s := &secureSession{
		insecure: insecure,
		ns: noiseState{
			initiator:   initiator,
			localStatic: kp,
		},
		localID:   tpt.localID,
		localKey:  tpt.privateKey,
		remoteID:  remote,
		msgBuffer: []byte{},
	}

	err = s.runHandshake(ctx)
	if err != nil {
		_ = s.insecure.Close()
	}
	return s, err
}

func (s *secureSession) LocalAddr() net.Addr {
	return s.insecure.LocalAddr()
}

func (s *secureSession) LocalPeer() peer.ID {
	return s.localID
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
	return s.remoteID
}

func (s *secureSession) RemotePublicKey() crypto.PubKey {
	return s.remoteKey
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
