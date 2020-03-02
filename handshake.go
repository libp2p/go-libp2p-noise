package noise

import (
	"context"
	"fmt"
	"github.com/gogo/protobuf/proto"

	"github.com/flynn/noise"

	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/peer"

	"github.com/libp2p/go-libp2p-noise/pb"
)

// payloadSigPrefix is prepended to our Noise static key before signing with
// our libp2p identity key.
const payloadSigPrefix = "noise-libp2p-static-key:"

var cipherSuite = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)

func (s *secureSession) setRemotePeerInfo(key []byte) (err error) {
	s.remote.libp2pKey, err = crypto.UnmarshalPublicKey(key)
	return err
}

func (s *secureSession) setRemotePeerID(key crypto.PubKey) (err error) {
	s.remotePeer, err = peer.IDFromPublicKey(key)
	return err
}

func (s *secureSession) verifyPayload(payload *pb.NoiseHandshakePayload, noiseKey []byte) (err error) {
	sig := payload.GetIdentitySig()
	msg := append([]byte(payloadSigPrefix), noiseKey[:]...)

	ok, err := s.RemotePublicKey().Verify(msg, sig)
	if err != nil {
		return err
	} else if !ok {
		return fmt.Errorf("did not verify payload")
	}

	return nil
}

func (s *secureSession) completeHandshake(cs1, cs2 *noise.CipherState) {
	if s.initiator {
		s.enc = cs1
		s.dec = cs2
	} else {
		s.enc = cs2
		s.dec = cs1
	}
	s.handshakeComplete = true
}

func (s *secureSession) sendHandshakeMessage(payload []byte) error {
	buf, cs1, cs2, err := s.hs.WriteMessage(nil, payload)
	if err != nil {
		return err
	}

	err = s.writeMsgInsecure(buf)
	if err != nil {
		return err
	}

	if cs1 != nil && cs2 != nil {
		s.completeHandshake(cs1, cs2)
	}
	return nil
}

func (s *secureSession) readHandshakeMessage() ([]byte, error) {
	raw, err := s.readMsgInsecure()
	if err != nil {
		return nil, err
	}
	msg, cs1, cs2, err := s.hs.ReadMessage(nil, raw)
	if err != nil {
		return nil, err
	}
	if cs1 != nil && cs2 != nil {
		s.completeHandshake(cs1, cs2)
	}
	return msg, nil
}

func keypairToDH(kp Keypair) noise.DHKey {
	return noise.DHKey{
		Private: kp.privateKey[:],
		Public:  kp.publicKey[:],
	}
}

// Runs the XX handshake
// XX:
//   -> e
//   <- e, ee, s, es
//   -> s, se
func (s *secureSession) runHandshake(ctx context.Context) (err error) {

	cfg := noise.Config{
		CipherSuite:      cipherSuite,
		Pattern:          noise.HandshakeXX,
		Initiator:        s.initiator,
		Prologue:         s.prologue,
		StaticKeypair:    keypairToDH(*s.noiseKeypair),
		EphemeralKeypair: noise.DHKey{},
	}

	hs, err := noise.NewHandshakeState(cfg)
	if err != nil {
		return fmt.Errorf("runHandshake err initializing handshake state: %s", err)
	}
	s.hs = hs

	// setup libp2p keys
	localKeyRaw, err := s.LocalPublicKey().Bytes()
	if err != nil {
		return fmt.Errorf("runHandshake err getting raw pubkey: %s", err)
	}

	// sign noise data for payload
	noise_pub := s.noiseKeypair.publicKey
	signedPayload, err := s.localKey.Sign(append([]byte(payloadSigPrefix), noise_pub[:]...))
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

	if s.initiator {
		// stage 0 //

		err = s.sendHandshakeMessage(nil)
		if err != nil {
			return fmt.Errorf("runHandshake stage 0 initiator fail: %s", err)
		}

		// stage 1 //

		var plaintext []byte
		// read reply
		plaintext, err = s.readHandshakeMessage()
		if err != nil {
			return fmt.Errorf("runHandshake initiator stage 1 fail: %s", err)
		}

		s.remote.noiseKey = s.hs.PeerStatic()

		// stage 2 //

		err = s.sendHandshakeMessage(payloadEnc)
		if err != nil {
			return fmt.Errorf("runHandshake stage=2 initiator=true err=%s", err)
		}

		// unmarshal payload
		nhp := new(pb.NoiseHandshakePayload)
		err = proto.Unmarshal(plaintext, nhp)
		if err != nil {
			return fmt.Errorf("runHandshake stage=2 initiator=true err=cannot unmarshal payload")
		}

		// set remote libp2p public key
		err = s.setRemotePeerInfo(nhp.GetIdentityKey())
		if err != nil {
			return fmt.Errorf("runHandshake stage=2 initiator=true read remote libp2p key fail")
		}

		// assert that remote peer ID matches libp2p public key
		pid, err := peer.IDFromPublicKey(s.RemotePublicKey())
		if pid != s.remotePeer {
			return fmt.Errorf("runHandshake stage=2 initiator=true check remote peer id err: expected %x got %x", s.remotePeer, pid)
		} else if err != nil {
			return fmt.Errorf("runHandshake stage 2 initiator check remote peer id err %s", err)
		}

		// verify payload is signed by libp2p key
		err = s.verifyPayload(nhp, s.remote.noiseKey)
		if err != nil {
			return fmt.Errorf("runHandshake stage=2 initiator=true verify payload err=%s", err)
		}

	} else {

		// stage 0 //

		var plaintext []byte
		nhp := new(pb.NoiseHandshakePayload)

		// read message
		plaintext, err = s.readHandshakeMessage()
		if err != nil {
			return fmt.Errorf("runHandshake stage=0 initiator=false err=%s", err)
		}

		// stage 1 //

		err = s.sendHandshakeMessage(payloadEnc)
		if err != nil {
			return fmt.Errorf("runHandshake stage=1 initiator=false err=%s", err)
		}

		// stage 2 //

		// read message
		plaintext, err = s.readHandshakeMessage()
		if err != nil {
			return fmt.Errorf("runHandshake stage=2 initiator=false err=%s", err)
		}

		// unmarshal payload
		err = proto.Unmarshal(plaintext, nhp)
		if err != nil {
			return fmt.Errorf("runHandshake stage=2 initiator=false err=cannot unmarshal payload")
		}

		// set remote libp2p public key
		err = s.setRemotePeerInfo(nhp.GetIdentityKey())
		if err != nil {
			return fmt.Errorf("runHandshake stage=2 initiator=false read remote libp2p key fail")
		}

		// set remote libp2p public key from payload
		err = s.setRemotePeerID(s.RemotePublicKey())
		if err != nil {
			return fmt.Errorf("runHandshake stage=2 initiator=false set remote peer id err=%s", err)
		}

		s.remote.noiseKey = s.hs.PeerStatic()

		// verify payload is signed by libp2p key
		err = s.verifyPayload(nhp, s.remote.noiseKey)
		if err != nil {
			return fmt.Errorf("runHandshake stage=2 initiator=false err=%s", err)
		}
	}

	return nil
}
