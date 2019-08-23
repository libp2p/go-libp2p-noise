package noise

import (
	"github.com/libp2p/go-libp2p-core/crypto"
)

type peerInfo struct {
	staticKey crypto.PubKey
	ephemeralKey crypto.PubKey
}