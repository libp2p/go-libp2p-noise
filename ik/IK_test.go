package ik

import (
	"crypto/rand"
	"testing"

	"github.com/gogo/protobuf/proto"

	"github.com/libp2p/go-libp2p-core/crypto"

	"github.com/libp2p/go-libp2p-noise/pb"
)

func TestHandshake(t *testing.T) {
	// generate local static noise key
	kp_init := GenerateKeypair()
	kp_resp := GenerateKeypair()

	payload_string := []byte("noise-libp2p-static-key:")
	prologue := []byte("/noise/0.0.0")

	// initiator setup
	init_pub := kp_init.PubKey()
	libp2p_priv_init, libp2p_pub_init, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	libp2p_pub_init_raw, err := libp2p_pub_init.Raw()
	if err != nil {
		t.Fatal(err)
	}
	libp2p_init_signed_payload, err := libp2p_priv_init.Sign(append(payload_string, init_pub[:]...))
	if err != nil {
		t.Fatal(err)
	}

	// respoonder setup
	resp_pub := kp_resp.PubKey()
	libp2p_priv_resp, libp2p_pub_resp, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	libp2p_pub_resp_raw, err := libp2p_pub_resp.Raw()
	if err != nil {
		t.Fatal(err)
	}
	libp2p_resp_signed_payload, err := libp2p_priv_resp.Sign(append(payload_string, resp_pub[:]...))
	if err != nil {
		t.Fatal(err)
	}

	// initiator: new IK noise session
	ns_init := InitSession(true, prologue, kp_init, kp_resp.PubKey())

	// responder: new IK noise session
	ns_resp := InitSession(false, prologue, kp_resp, [32]byte{})

	// stage 0: initiator
	// create payload
	payload_init := new(pb.NoiseHandshakePayload)
	payload_init.IdentityKey = libp2p_pub_init_raw
	payload_init.IdentitySig = libp2p_init_signed_payload
	payload_init_enc, err := proto.Marshal(payload_init)
	if err != nil {
		t.Fatalf("proto marshal payload fail: %s", err)
	}

	// send message
	var msgbuf MessageBuffer
	msg := []byte{}
	msg = append(msg, payload_init_enc[:]...)
	ns_init, msgbuf = SendMessage(ns_init, msg)

	t.Logf("stage 0 msgbuf: %v", msgbuf)
	t.Logf("stage 0 msgbuf ne len: %d", len(msgbuf.NE()))

	// stage 0: responder
	var plaintext []byte
	var valid bool
	ns_resp, plaintext, valid = RecvMessage(ns_resp, &msgbuf)
	if !valid {
		t.Fatalf("stage 0 receive not valid")
	}

	t.Logf("stage 0 resp payload: %x", plaintext)

	// stage 1: responder
	// create payload
	payload_resp := new(pb.NoiseHandshakePayload)
	payload_resp.IdentityKey = libp2p_pub_resp_raw
	payload_resp.IdentitySig = libp2p_resp_signed_payload
	payload_resp_enc, err := proto.Marshal(payload_resp)
	if err != nil {
		t.Fatalf("proto marshal payload fail: %s", err)
	}
	msg = append(msg, payload_resp_enc[:]...)
	ns_resp, msgbuf = SendMessage(ns_resp, msg)

	t.Logf("stage 1 msgbuf: %v", msgbuf)
	t.Logf("stage 1 msgbuf ne len: %d", len(msgbuf.NE()))
	t.Logf("stage 1 msgbuf ns len: %d", len(msgbuf.NS()))

	// stage 1: initiator
	ns_init, plaintext, valid = RecvMessage(ns_init, &msgbuf)
	if !valid {
		t.Fatalf("stage 1 receive not valid")
	}

	t.Logf("stage 1 resp payload: %x", plaintext)

}
