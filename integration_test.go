package noise

import (
	"context"
	"crypto/rand"
	"fmt"
	libp2p "github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/peer"
	ma "github.com/multiformats/go-multiaddr"
	"io"
	mrand "math/rand"
	"testing"
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
		libp2p.Security("/noise/0.0.1", tpt),
		libp2p.ListenAddrs(addr),
	}

	ctx := context.Background()

	return libp2p.New(ctx, options...)
}

func TestLibp2pIntegration(t *testing.T) {
	// ctx := context.Background()

	// ha, err := makeNode(t, 1, 33333)
	// if err != nil {
	// 	t.Fatal(err)
	// }

	// fmt.Printf("ha: %s/ipfs/%s\n", ha.Addrs()[1].String(), ha.ID())

	// hb, err := makeNode(t, 2, 34343)
	// if err != nil {
	// 	t.Fatal(err)
	// }

	// addr, err := ma.NewMultiaddr(fmt.Sprintf("%s/ipfs/%s", hb.Addrs()[1].String(), hb.ID()))
	// if err != nil {
	// 	t.Fatal(err)
	// }

	// fmt.Printf("hb: %s\n", addr)

	// addrInfo, err := peer.AddrInfoFromP2pAddr(addr)
	// if err != nil {
	// 	t.Fatal(err)
	// }

	// err = ha.Connect(ctx, *addrInfo)
	// if err != nil {
	// 	t.Fatal(err)
	// }

	fmt.Println("noot")
}
