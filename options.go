package noise

// UseNoisePipes configures the Noise transport to use the Noise Pipes pattern.
// Noise Pipes attempts to use the more efficient IK handshake pattern when
// dialing a remote peer, if that peer's static Noise key is known. If this
// is unsuccessful, the transport will fallback to using the default XX pattern.
//
// Note that the fallback does not add any additional round-trips vs. simply
// using XX in the first place, however there is a slight processing overhead
// due to the initial decryption attempt of the IK message.
func UseNoisePipes(cfg *config) {
	cfg.NoisePipesSupport = true
}

// NoiseKeyPair configures the Noise transport to use the given Noise static
// keypair. This is distinct from the libp2p Host's identity keypair and is
// used only for Noise. If this option is not provided, a new Noise static
// keypair will be generated when the transport is initialized.
//
// This option is most useful when Noise Pipes is enabled, as longer static
// key lifetimes may lead to more successful IK handshake attempts.
//
// If you do use this option with a key that's been saved to disk, you must
// take care to store the key securely!
func NoiseKeyPair(kp *Keypair) Option {
	return func(cfg *config) {
		cfg.NoiseKeypair = kp
	}
}

type config struct {
	NoiseKeypair      *Keypair
	NoisePipesSupport bool
}

type Option func(cfg *config)

func (cfg *config) applyOptions(opts ...Option) {
	for _, opt := range opts {
		if opt != nil {
			opt(cfg)
		}
	}
}
