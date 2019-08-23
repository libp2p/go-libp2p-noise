package xx

import (
	"encoding/hex"
	"testing"

	"github.com/ChainSafe/go-libp2p-noise"
)

func TestGetHkdf(t *testing.T) {
	ck := [32]byte{}
	ckBytes, err := hex.DecodeString("4e6f6973655f58585f32353531395f58436861436861506f6c795f53484132353600000000000000000000000000000000000000000000000000000000000000")	
	if err != nil {
		t.Fatal(err)
	}
	copy(ck[:], ckBytes)

	ikm, err := hex.DecodeString("a3eae50ea37a47e8a7aa0c7cd8e16528670536dcd538cebfd724fb68ce44f1910ad898860666227d4e8dd50d22a9a64d1c0a6f47ace092510161e9e442953da3")
	if err != nil {
		t.Fatal(err)
	}

	a, b, c := getHkdf(ck, ikm)
	t.Logf("%x", a)
	t.Logf("%x", b)
	t.Logf("%x", c)
}

func TestHandshake(t *testing.T) {
	// generate local static noise key
	kp_init := GenerateKeypair()
	kp_remote := GenerateKeypair()

	prologue := []byte("/noise/0.0.0")

	// new XX noise session
	ns_init := InitSession(true, prologue, kp_init, kp_remote.PublicKey())

	// create payload
	payload := new(noise.NoiseHandshakePayload)
	msg, err := proto.Marshal(payload)
	if err != nil {
		return fmt.Errorf("proto marshal payload fail: %s", err)
	}
	
	var msgbuf MessageBuffer
	ns, msgbuf = SendMessage(ns, msg)

	encMsgBuf := msgbuf.Encode0()
	if len(encMsgBuf) != 56 {
		return fmt.Errorf("enc msg buf: len does not equal 56")
	}

	_, err = s.insecure.Write(encMsgBuf)
	if err != nil {
		return fmt.Errorf("write to conn fail: %s", err)
	}

	buf := make([]byte, 144)
	_, err = s.insecure.Read(buf)
	if err != nil {
		return fmt.Errorf("read from conn fail: %s", err)
	}

	var plaintext []byte
	var valid bool
	ns, plaintext, valid = RecvMessage()
}