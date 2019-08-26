package noise

import (
	"bufio"
	"context"
	"crypto/rand"
	"fmt"
	libp2p "github.com/libp2p/go-libp2p"
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

func makeNode(t *testing.T, seed int64, port int) (host.Host, error) {
	priv, err := generateKey(seed)
	if err != nil {
		t.Fatal(err)
	}

	pid, err := peer.IDFromPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}

	tpt := NewTransport(pid, priv, false)

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

	//fmt.Printf("ha: %s/p2p/%s\n", ha.Addrs()[1].String(), ha.ID())

	hb, err := makeNode(t, 2, 34343)
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
	fmt.Println("got msg:", msg)
}
