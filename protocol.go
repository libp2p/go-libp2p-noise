package noise

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/gogo/protobuf/proto"
	logging "github.com/ipfs/go-log"
	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/peer"

	"github.com/libp2p/go-libp2p-noise/ik"
	"github.com/libp2p/go-libp2p-noise/pb"
	"github.com/libp2p/go-libp2p-noise/xx"
)

const payload_string = "noise-libp2p-static-key:"

// Each encrypted transport message must be <= 65,535 bytes, including 16
// bytes of authentication data. To write larger plaintexts, we split them
// into fragments of maxPlaintextLength before encrypting.
const maxPlaintextLength = 65519

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

	xx_ns *xx.NoiseSession
	ik_ns *ik.NoiseSession

	xx_complete bool
	ik_complete bool

	noisePipesSupport   bool
	noiseStaticKeyCache *KeyCache

	noiseKeypair *Keypair

	msgBuffer []byte
	readLock  sync.Mutex
	writeLock sync.Mutex
}

type peerInfo struct {
	noiseKey  [32]byte // static noise public key
	libp2pKey crypto.PubKey
}

// newSecureSession creates a noise session over the given insecure Conn, using the static
// Noise keypair and libp2p identity keypair from the given Transport.
//
// If tpt.noisePipesSupport == true, the Noise Pipes handshake protocol will be used,
// which consists of the IK and XXfallback handshake patterns. With Noise Pipes on, we first try IK,
// if that fails, move to XXfallback. With Noise Pipes off, we always do XX.
func newSecureSession(tpt *Transport, ctx context.Context, insecure net.Conn, remote peer.ID, initiator bool) (*secureSession, error) {
	if tpt.noiseKeypair == nil {
		return nil, errNoKeypair
	}

	// if the transport doesn't have a key cache, we make a new one just for
	// this session. it's a bit of a waste, but saves us having to check if
	// it's nil later
	keyCache := tpt.noiseStaticKeyCache
	if keyCache == nil {
		keyCache = NewKeyCache()
	}

	localPeerInfo := peerInfo{
		noiseKey:  tpt.noiseKeypair.publicKey,
		libp2pKey: tpt.privateKey.GetPublic(),
	}

	s := &secureSession{
		insecure:            insecure,
		initiator:           initiator,
		prologue:            []byte{},
		localKey:            tpt.privateKey,
		localPeer:           tpt.localID,
		remotePeer:          remote,
		local:               localPeerInfo,
		noisePipesSupport:   tpt.noisePipesSupport,
		noiseStaticKeyCache: keyCache,
		msgBuffer:           []byte{},
		noiseKeypair:        tpt.noiseKeypair,
	}

	err := s.runHandshake(ctx)

	return s, err
}

func (s *secureSession) NoiseStaticKeyCache() *KeyCache {
	return s.noiseStaticKeyCache
}

func (s *secureSession) NoisePublicKey() [32]byte {
	return s.noiseKeypair.publicKey
}

func (s *secureSession) NoisePrivateKey() [32]byte {
	return s.noiseKeypair.privateKey
}

func (s *secureSession) readLength() (int, error) {
	buf := make([]byte, 2)
	_, err := io.ReadFull(s.insecure, buf)
	return int(binary.BigEndian.Uint16(buf)), err
}

func (s *secureSession) writeLength(length int) error {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, uint16(length))
	_, err := s.insecure.Write(buf)
	return err
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
	sig := payload.GetIdentitySig()
	msg := append([]byte(payload_string), noiseKey[:]...)

	log.Debugf("verifyPayload msg=%x", msg)

	ok, err := s.RemotePublicKey().Verify(msg, sig)
	if err != nil {
		return err
	} else if !ok {
		return fmt.Errorf("did not verify payload")
	}

	return nil
}

func (s *secureSession) runHandshake(ctx context.Context) error {
	// setup libp2p keys
	localKeyRaw, err := s.LocalPublicKey().Bytes()
	if err != nil {
		return fmt.Errorf("runHandshake err getting raw pubkey: %s", err)
	}

	// sign noise data for payload
	noise_pub := s.noiseKeypair.publicKey
	signedPayload, err := s.localKey.Sign(append([]byte(payload_string), noise_pub[:]...))
	if err != nil {
		return fmt.Errorf("runHandshake signing payload err=%s", err)
	}

	// create payload
	payload := new(pb.NoiseHandshakePayload)
	payload.IdentityKey = localKeyRaw
	payload.IdentitySig = signedPayload
	payloadEnc, err := proto.Marshal(payload)
	if err != nil {
		return fmt.Errorf("runHandshake proto marshal payload err=%s", err)
	}

	// If we support Noise pipes, we try IK first, falling back to XX if IK fails.
	// The exception is when we're the initiator and don't know the other party's
	// static Noise key. Then IK will always fail, so we go straight to XX.
	tryIK := s.noisePipesSupport
	if s.initiator && s.noiseStaticKeyCache.Load(s.remotePeer) == [32]byte{} {
		tryIK = false
	}
	if tryIK {
		// we're either a responder or an initiator with a known static key for the remote peer, try IK
		buf, err := s.runHandshake_ik(ctx, payloadEnc)
		if err != nil {
			// IK failed, pipe to XXfallback
			err = s.runHandshake_xx(ctx, true, payloadEnc, buf)
			if err != nil {
				return fmt.Errorf("runHandshake xx err=%s", err)
			}

			s.xx_complete = true
		} else {
			s.ik_complete = true
		}
	} else {
		// unknown static key for peer, try XX
		err := s.runHandshake_xx(ctx, false, payloadEnc, nil)
		if err != nil {
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
	s.readLock.Lock()
	defer s.readLock.Unlock()

	l := len(buf)

	// if we have previously unread bytes, and they fit into the buf, copy them over and return
	if l <= len(s.msgBuffer) {
		copy(buf, s.msgBuffer)
		s.msgBuffer = s.msgBuffer[l:]
		return l, nil
	}

	readChunk := func(buf []byte) (int, error) {
		// read length of encrypted message
		l, err := s.readLength()
		if err != nil {
			return 0, err
		}

		// read and decrypt ciphertext
		ciphertext := make([]byte, l)
		_, err = io.ReadFull(s.insecure, ciphertext)
		if err != nil {
			return 0, err
		}

		plaintext, err := s.Decrypt(ciphertext)
		if err != nil {
			return 0, err
		}

		// append plaintext to message buffer, copy over what can fit in the buf
		// then advance message buffer to remove what was copied
		s.msgBuffer = append(s.msgBuffer, plaintext...)
		c := copy(buf, s.msgBuffer)
		s.msgBuffer = s.msgBuffer[c:]
		return c, nil
	}

	total := 0
	for i := 0; i < len(buf); i += maxPlaintextLength {
		end := i + maxPlaintextLength
		if end > len(buf) {
			end = len(buf)
		}

		c, err := readChunk(buf[i:end])
		total += c
		if err != nil {
			return total, err
		}
	}

	return total, nil
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
	s.writeLock.Lock()
	defer s.writeLock.Unlock()

	writeChunk := func(in []byte) (int, error) {
		ciphertext, err := s.Encrypt(in)
		if err != nil {
			return 0, err
		}

		err = s.writeLength(len(ciphertext))
		if err != nil {
			return 0, err
		}

		_, err = s.insecure.Write(ciphertext)
		return len(in), err
	}

	written := 0
	for i := 0; i < len(in); i += maxPlaintextLength {
		end := i + maxPlaintextLength
		if end > len(in) {
			end = len(in)
		}

		l, err := writeChunk(in[i:end])
		written += l
		if err != nil {
			return written, err
		}
	}
	return written, nil
}

func (s *secureSession) Close() error {
	return s.insecure.Close()
}
