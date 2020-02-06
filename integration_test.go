package noise

import (
	"context"
	"crypto/rand"
	"fmt"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/host"
	net "github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-noise/core"
	ma "github.com/multiformats/go-multiaddr"
	"io"
	"io/ioutil"
	mrand "math/rand"
	"testing"
	"time"
)

const testProtocolID = "/test/noise/integration"

func generateKey(seed int64) (crypto.PrivKey, error) {
	var r io.Reader
	if seed == 0 {
		r = rand.Reader
	} else {
		r = mrand.New(mrand.NewSource(seed))
	}

	priv, _, err := crypto.GenerateKeyPairWithReader(crypto.Ed25519, 2048, r)
	if err != nil {
		return nil, err
	}

	return priv, nil
}

func makeNode(t *testing.T, seed int64, port int, kp *core.Keypair) (host.Host, error) {
	priv, err := generateKey(seed)
	if err != nil {
		t.Fatal(err)
	}

	tpt, err := New(priv, NoiseKeyPair(kp))
	if err != nil {
		t.Fatal(err)
	}
	ip := "0.0.0.0"
	addr, err := ma.NewMultiaddr(fmt.Sprintf("/ip4/%s/tcp/%d", ip, port))
	if err != nil {
		t.Fatal(err)
	}

	options := []libp2p.Option{
		libp2p.Identity(priv),
		libp2p.Security(ID, tpt),
		libp2p.ListenAddrs(addr),
	}

	ctx := context.Background()

	return libp2p.New(ctx, options...)
}

func makeNodePipes(t *testing.T, seed int64, port int, rpid peer.ID, rpubkey [32]byte, kp *core.Keypair) (host.Host, error) {
	priv, err := generateKey(seed)
	if err != nil {
		t.Fatal(err)
	}

	tpt, err := New(priv, UseNoisePipes, NoiseKeyPair(kp))
	if err != nil {
		t.Fatal(err)
	}

	tpt.noiseStaticKeyCache = NewKeyCache()
	tpt.noiseStaticKeyCache.Store(rpid, rpubkey)

	ip := "0.0.0.0"
	addr, err := ma.NewMultiaddr(fmt.Sprintf("/ip4/%s/tcp/%d", ip, port))
	if err != nil {
		t.Fatal(err)
	}

	options := []libp2p.Option{
		libp2p.Identity(priv),
		libp2p.Security(ID, tpt),
		libp2p.ListenAddrs(addr),
	}

	ctx := context.Background()

	h, err := libp2p.New(ctx, options...)
	return h, err
}

func TestLibp2pIntegration_NoPipes(t *testing.T) {
	ctx := context.Background()

	ha, err := makeNode(t, 1, 33333, nil)
	if err != nil {
		t.Fatal(err)
	}

	defer ha.Close()

	hb, err := makeNode(t, 2, 34343, nil)
	if err != nil {
		t.Fatal(err)
	}

	defer hb.Close()

	ha.SetStreamHandler(testProtocolID, streamHandler(t))
	hb.SetStreamHandler(testProtocolID, streamHandler(t))

	addr, err := ma.NewMultiaddr(fmt.Sprintf("%s/p2p/%s", hb.Addrs()[0].String(), hb.ID()))
	if err != nil {
		t.Fatal(err)
	}

	fmt.Printf("hb: %s\n", addr)

	addrInfo, err := peer.AddrInfoFromP2pAddr(addr)
	if err != nil {
		t.Fatal(err)
	}

	err = ha.Connect(ctx, *addrInfo)
	if err != nil {
		t.Fatal(err)
	}

	stream, err := ha.NewStream(ctx, hb.ID(), testProtocolID)
	if err != nil {
		t.Fatal(err)
	}

	err = writeRandomPayloadAndClose(t, stream)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println("fin")

	time.Sleep(time.Second)
}

func TestLibp2pIntegration_WithPipes(t *testing.T) {
	ctx := context.Background()

	kpa := core.GenerateKeypair()

	ha, err := makeNodePipes(t, 1, 33333, "", [32]byte{}, &kpa)
	if err != nil {
		t.Fatal(err)
	}

	defer ha.Close()

	hb, err := makeNodePipes(t, 2, 34343, ha.ID(), kpa.PubKey(), nil)
	if err != nil {
		t.Fatal(err)
	}

	defer hb.Close()

	ha.SetStreamHandler(testProtocolID, streamHandler(t))
	hb.SetStreamHandler(testProtocolID, streamHandler(t))

	addr, err := ma.NewMultiaddr(fmt.Sprintf("%s/p2p/%s", ha.Addrs()[0].String(), ha.ID()))
	if err != nil {
		t.Fatal(err)
	}

	fmt.Printf("ha: %s\n", addr)

	addrInfo, err := peer.AddrInfoFromP2pAddr(addr)
	if err != nil {
		t.Fatal(err)
	}

	err = hb.Connect(ctx, *addrInfo)
	if err != nil {
		t.Fatal(err)
	}

	stream, err := hb.NewStream(ctx, ha.ID(), testProtocolID)
	if err != nil {
		t.Fatal(err)
	}

	err = writeRandomPayloadAndClose(t, stream)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println("fin")

	time.Sleep(time.Second)
}

func TestLibp2pIntegration_XXFallback(t *testing.T) {
	ctx := context.Background()

	kpa := core.GenerateKeypair()

	ha, err := makeNode(t, 1, 33333, &kpa)
	if err != nil {
		t.Fatal(err)
	}

	defer ha.Close()

	hb, err := makeNodePipes(t, 2, 34343, ha.ID(), kpa.PubKey(), nil)
	if err != nil {
		t.Fatal(err)
	}

	defer hb.Close()

	ha.SetStreamHandler(testProtocolID, streamHandler(t))
	hb.SetStreamHandler(testProtocolID, streamHandler(t))

	addr, err := ma.NewMultiaddr(fmt.Sprintf("%s/p2p/%s", hb.Addrs()[0].String(), hb.ID()))
	if err != nil {
		t.Fatal(err)
	}

	fmt.Printf("ha: %s\n", addr)

	addrInfo, err := peer.AddrInfoFromP2pAddr(addr)
	if err != nil {
		t.Fatal(err)
	}

	err = ha.Connect(ctx, *addrInfo)
	if err != nil {
		t.Fatal(err)
	}

	stream, err := hb.NewStream(ctx, ha.ID(), testProtocolID)
	if err != nil {
		t.Fatal(err)
	}

	err = writeRandomPayloadAndClose(t, stream)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println("fin")

	time.Sleep(time.Second)
}

func TestConstrucingWithMaker(t *testing.T) {
	kp := core.GenerateKeypair()

	ctx := context.Background()
	h, err := libp2p.New(ctx,
		libp2p.Security(ID,
			Maker(NoiseKeyPair(&kp), UseNoisePipes)))

	if err != nil {
		t.Fatalf("unable to create libp2p host with Maker: %v", err)
	}
	_ = h.Close()
}

func writeRandomPayloadAndClose(t *testing.T, stream net.Stream) error {
	t.Helper()
	size := 1 << 24
	r := mrand.New(mrand.NewSource(42))
	start := time.Now()
	lr := io.LimitReader(r, int64(size))

	c, err := io.Copy(stream, lr)
	elapsed := time.Since(start)
	if err != nil {
		return fmt.Errorf("failed to write out bytes: %v", err)
	}
	t.Logf("wrote %d bytes in %dms", c, elapsed.Milliseconds())
	return stream.Close()
}

func streamHandler(t *testing.T) func(net.Stream) {
	return func(stream net.Stream) {
		t.Helper()
		defer func() {
			if err := stream.Close(); err != nil {
				t.Error("error closing stream: ", err)
			}
		}()

		start := time.Now()
		c, err := io.Copy(ioutil.Discard, stream)
		elapsed := time.Since(start)
		if err != nil {
			t.Error("error reading from stream: ", err)
			return
		}
		t.Logf("read %d bytes in %dms", c, elapsed.Milliseconds())
	}
}
