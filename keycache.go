package noise

import (
	"sync"

	"github.com/libp2p/go-libp2p-core/peer"
)

type KeyCache struct {
	lock sync.RWMutex
	m    map[peer.ID][32]byte
}

func NewKeyCache() *KeyCache {
	return &KeyCache{
		m: make(map[peer.ID][32]byte),
	}
}

func (kc *KeyCache) Store(p peer.ID, key [32]byte) {
	kc.lock.Lock()
	kc.m[p] = key
	kc.lock.Unlock()
}

func (kc *KeyCache) Load(p peer.ID) [32]byte {
	kc.lock.RLock()
	defer kc.lock.RUnlock()
	return kc.m[p]
}
