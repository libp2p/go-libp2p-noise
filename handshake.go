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

func (s *secureSession) setRemotePeerInfo(keyBytes []byte) (err error) {
	key, err := crypto.UnmarshalPublicKey(keyBytes)
	if err != nil {
		return err
	}
	id, err := peer.IDFromPublicKey(key)
	if err != nil {
		return err
	}

	if s.remoteID != "" && s.remoteID != id {
		return fmt.Errorf("peer id mismatch: expected %s, but remote key matches %s", s.remoteID, id)
	}

	s.remoteID = id
	s.remoteKey = key
	return nil
}

func (s *secureSession) verifyPayload(payload *pb.NoiseHandshakePayload, noiseKey []byte) (err error) {
	sig := payload.GetIdentitySig()
	msg := append([]byte(payloadSigPrefix), noiseKey...)

	ok, err := s.RemotePublicKey().Verify(msg, sig)
	if err != nil {
		return err
	} else if !ok {
		return fmt.Errorf("did not verify payload")
	}

	return nil
}

func (s *secureSession) completeHandshake(cs1, cs2 *noise.CipherState) {
	if s.ns.initiator {
		s.ns.enc = cs1
		s.ns.dec = cs2
	} else {
		s.ns.enc = cs2
		s.ns.dec = cs1
	}
}

func (s *secureSession) sendHandshakeMessage(payload []byte) error {
	buf, cs1, cs2, err := s.ns.hs.WriteMessage(nil, payload)
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
	msg, cs1, cs2, err := s.ns.hs.ReadMessage(nil, raw)
	if err != nil {
		return nil, err
	}
	if cs1 != nil && cs2 != nil {
		s.completeHandshake(cs1, cs2)
	}
	return msg, nil
}

func (s *secureSession) generateHandshakePayload() ([]byte, error) {
	// setup libp2p keys
	localKeyRaw, err := s.LocalPublicKey().Bytes()
	if err != nil {
		return nil, fmt.Errorf("error serializing libp2p identity key: %s", err)
	}

	// sign noise data for payload
	toSign := append([]byte(payloadSigPrefix), s.ns.localStatic.Public...)
	signedPayload, err := s.localKey.Sign(toSign)
	if err != nil {
		return nil, fmt.Errorf("error sigining handshake payload: %s", err)
	}

	// create payload
	payload := new(pb.NoiseHandshakePayload)
	payload.IdentityKey = localKeyRaw
	payload.IdentitySig = signedPayload
	payloadEnc, err := proto.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("error marshaling handshake payload: %s", err)
	}
	return payloadEnc, nil
}

// Runs the XX handshake
// XX:
//   -> e
//   <- e, ee, s, es
//   -> s, se
func (s *secureSession) runHandshake(ctx context.Context) (err error) {

	cfg := noise.Config{
		CipherSuite:   cipherSuite,
		Pattern:       noise.HandshakeXX,
		Initiator:     s.ns.initiator,
		StaticKeypair: s.ns.localStatic,
	}

	hs, err := noise.NewHandshakeState(cfg)
	if err != nil {
		return fmt.Errorf("error initializing handshake state: %s", err)
	}
	s.ns.hs = hs

	payload, err := s.generateHandshakePayload()
	if err != nil {
		return err
	}

	if s.ns.initiator {
		// stage 0 //

		err = s.sendHandshakeMessage(nil)
		if err != nil {
			return fmt.Errorf("error sending handshake message: %s", err)
		}

		// stage 1 //

		// read reply
		plaintext, err := s.readHandshakeMessage()
		if err != nil {
			return fmt.Errorf("error reading handshake message: %s", err)
		}

		// stage 2 //
		err = s.sendHandshakeMessage(payload)
		if err != nil {
			return fmt.Errorf("error sending handshake message: %s", err)
		}

		// unmarshal payload
		nhp := new(pb.NoiseHandshakePayload)
		err = proto.Unmarshal(plaintext, nhp)
		if err != nil {
			return fmt.Errorf("error unmarshaling remote handshake payload: %s", err)
		}

		// set remote libp2p public key
		err = s.setRemotePeerInfo(nhp.GetIdentityKey())
		if err != nil {
			return fmt.Errorf("error processing remote libp2p key: %s", err)
		}

		// verify payload is signed by libp2p key
		err = s.verifyPayload(nhp, s.ns.hs.PeerStatic())
		if err != nil {
			return fmt.Errorf("error validating handshake signature: %s", err)
		}

	} else {

		// stage 0 //
		var plaintext []byte
		nhp := new(pb.NoiseHandshakePayload)

		// read message
		plaintext, err = s.readHandshakeMessage()
		if err != nil {
			return fmt.Errorf("error reading handshake message: %s", err)
		}

		// stage 1 //

		err = s.sendHandshakeMessage(payload)
		if err != nil {
			return fmt.Errorf("error sending handshake message: %s", err)
		}

		// stage 2 //

		// read message
		plaintext, err = s.readHandshakeMessage()
		if err != nil {
			return fmt.Errorf("error reading handshake message: %s", err)
		}

		// unmarshal payload
		err = proto.Unmarshal(plaintext, nhp)
		if err != nil {
			return fmt.Errorf("error unmarshaling remote handshake payload: %s", err)
		}

		// set remote libp2p public key
		err = s.setRemotePeerInfo(nhp.GetIdentityKey())
		if err != nil {
			return fmt.Errorf("error processing remote libp2p key: %s", err)
		}

		// verify payload is signed by libp2p key
		err = s.verifyPayload(nhp, s.ns.hs.PeerStatic())
		if err != nil {
			return fmt.Errorf("error validating handshake signature: %s", err)
		}
	}

	return nil
}
