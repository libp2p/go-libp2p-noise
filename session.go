package noise

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/flynn/noise"

	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/peer"
)

type secureSession struct {
	initiator bool

	localID   peer.ID
	localKey  crypto.PrivKey
	remoteID  peer.ID
	remoteKey crypto.PubKey

	insecure  net.Conn
	msgBuffer []byte
	readLock  sync.Mutex
	writeLock sync.Mutex

	enc *noise.CipherState
	dec *noise.CipherState
}

// newSecureSession creates a noise session over the given insecure Conn, using the
// libp2p identity keypair from the given Transport.
func newSecureSession(tpt *Transport, ctx context.Context, insecure net.Conn, remote peer.ID, initiator bool) (*secureSession, error) {
	s := &secureSession{
		insecure:  insecure,
		initiator: initiator,
		localID:   tpt.localID,
		localKey:  tpt.privateKey,
		remoteID:  remote,
	}

	err := s.runHandshake(ctx)
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
