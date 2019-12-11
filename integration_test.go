package noise

import (
	"bufio"
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
	mrand "math/rand"
	"testing"
	"time"
)

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

func makeNode(t *testing.T, seed int64, port int, kp *Keypair) (host.Host, error) {
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

func makeNodePipes(t *testing.T, seed int64, port int, rpid peer.ID, rpubkey [32]byte, kp *Keypair) (host.Host, error) {
	priv, err := generateKey(seed)
	if err != nil {
		t.Fatal(err)
	}

	tpt, err := New(priv, UseNoisePipes, NoiseKeyPair(kp))
	if err != nil {
		t.Fatal(err)
	}

	tpt.NoiseStaticKeyCache = NewKeyCache()
	tpt.NoiseStaticKeyCache.Store(rpid, rpubkey)

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

	ha.SetStreamHandler(ID, handleStream)
	hb.SetStreamHandler(ID, handleStream)

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

	stream, err := ha.NewStream(ctx, hb.ID(), ID)
	if err != nil {
		t.Fatal(err)
	}

	_, err = stream.Write([]byte("hello\n"))
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println("fin")

	time.Sleep(time.Second)
}

func TestLibp2pIntegration_WithPipes(t *testing.T) {
	ctx := context.Background()

	kpa := GenerateKeypair()

	ha, err := makeNodePipes(t, 1, 33333, "", [32]byte{}, kpa)
	if err != nil {
		t.Fatal(err)
	}

	defer ha.Close()

	hb, err := makeNodePipes(t, 2, 34343, ha.ID(), kpa.public_key, nil)
	if err != nil {
		t.Fatal(err)
	}

	defer hb.Close()

	ha.SetStreamHandler(ID, handleStream)
	hb.SetStreamHandler(ID, handleStream)

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

	stream, err := hb.NewStream(ctx, ha.ID(), ID)
	if err != nil {
		t.Fatal(err)
	}

	_, err = stream.Write([]byte("hello\n"))
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println("fin")

	time.Sleep(time.Second)
}

func TestLibp2pIntegration_XXFallback(t *testing.T) {
	ctx := context.Background()

	kpa := GenerateKeypair()

	ha, err := makeNode(t, 1, 33333, kpa)
	if err != nil {
		t.Fatal(err)
	}

	defer ha.Close()

	hb, err := makeNodePipes(t, 2, 34343, ha.ID(), kpa.public_key, nil)
	if err != nil {
		t.Fatal(err)
	}

	defer hb.Close()

	ha.SetStreamHandler(ID, handleStream)
	hb.SetStreamHandler(ID, handleStream)

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

	stream, err := hb.NewStream(ctx, ha.ID(), ID)
	if err != nil {
		t.Fatal(err)
	}

	_, err = stream.Write([]byte("hello\n"))
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println("fin")

	time.Sleep(time.Second)
}

func TestConstrucingWithMaker(t *testing.T) {
	kp := GenerateKeypair()

	ctx := context.Background()
	h, err := libp2p.New(ctx,
		libp2p.Security(ID,
			Maker(NoiseKeyPair(kp), UseNoisePipes)))

	if err != nil {
		t.Fatalf("unable to create libp2p host with Maker: %v", err)
	}
	_ = h.Close()
}

func handleStream(stream net.Stream) {
	defer func() {
		if err := stream.Close(); err != nil {
			log.Error("error closing stream", "err", err)
		}
	}()

	rw := bufio.NewReadWriter(bufio.NewReader(stream), bufio.NewWriter(stream))
	msg, err := rw.Reader.ReadString('\n')
	if err != nil {
		fmt.Println("stream err", err)
		return
	}
	fmt.Printf("got msg: %s", msg)
}
