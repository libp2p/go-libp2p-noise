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

func makeNode(t *testing.T, seed int64, port int) (host.Host, error) {
	priv, err := generateKey(seed)
	if err != nil {
		t.Fatal(err)
	}

	tpt, err := New(priv)
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

func TestLibp2pIntegration(t *testing.T) {
	ctx := context.Background()

	ha, err := makeNode(t, 1, 33333)
	if err != nil {
		t.Fatal(err)
	}

	defer ha.Close()

	hb, err := makeNode(t, 2, 34343)
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
