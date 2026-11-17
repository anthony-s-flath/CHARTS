package charts

import (
	"fmt"
	"runtime"
	"sync"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/multiparty"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
	"github.com/tuneinsight/lattigo/v6/utils/sampling"
)

// Keys are the collective public and evaluation keys.
type Keys struct {
	PublicKey  *rlwe.PublicKey
	RelinKey   *rlwe.RelinearizationKey
	GaloisKeys []*rlwe.GaloisKey
}

// PartialDecryption contains one sender's shares for the complete router output.
type PartialDecryption struct {
	Header   multiparty.KeySwitchShare
	Payloads []multiparty.KeySwitchShare
}

// NewSenders creates n routing secret-key shares and the collective routing
// keys. This setup models the sender MPC from the CHARTS manuscript; receiver
// setup belongs to the separate registration phase.
func NewSenders(
	params bgv.Parameters,
	n int,
	b int,
	seed []byte,
) ([]*Sender, Keys, error) {
	layout, err := newRoutingLayout(params, n, b)
	if err != nil {
		return nil, Keys{}, err
	}
	galoisElements, err := galoisElements(params, n, b)
	if err != nil {
		return nil, Keys{}, err
	}

	crs, err := sampling.NewKeyedPRNG(append([]byte(nil), seed...))
	if err != nil {
		return nil, Keys{}, err
	}
	shares := make([]*rlwe.SecretKey, n)
	keyGenerator := rlwe.NewKeyGenerator(params)
	for i := range shares {
		shares[i] = keyGenerator.GenSecretKeyNew()
	}

	keys := Keys{
		PublicKey: generatePublicKey(params, shares, crs),
	}
	// The direct b=n circuit only adds ciphertexts. It needs neither
	// relinearization nor automorphism keys (or their MPC protocols).
	if layout.factorCount > 1 {
		keys.RelinKey = generateRelinKey(params, shares, crs)
		keys.GaloisKeys, err = generateGaloisKeys(params, shares, crs, galoisElements)
		if err != nil {
			return nil, Keys{}, err
		}
	}

	senders := make([]*Sender, n)
	for i, share := range shares {
		senders[i], err = NewSender(params, keys.PublicKey, share, n, b)
		if err != nil {
			return nil, Keys{}, err
		}
	}
	return senders, keys, nil
}

func generatePublicKey(
	params bgv.Parameters,
	shares []*rlwe.SecretKey,
	crs multiparty.CRS,
) *rlwe.PublicKey {
	protocol := multiparty.NewPublicKeyGenProtocol(params)
	crp := protocol.SampleCRP(crs)
	combined := protocol.AllocateShare()
	for _, secretKeyShare := range shares {
		share := protocol.AllocateShare()
		protocol.GenShare(secretKeyShare, crp, &share)
		protocol.AggregateShares(share, combined, &combined)
	}
	publicKey := rlwe.NewPublicKey(params)
	protocol.GenPublicKey(combined, crp, publicKey)
	return publicKey
}

func generateRelinKey(
	params bgv.Parameters,
	shares []*rlwe.SecretKey,
	crs multiparty.CRS,
) *rlwe.RelinearizationKey {
	protocol := multiparty.NewRelinearizationKeyGenProtocol(params)
	crp := protocol.SampleCRP(crs)
	eph := make([]*rlwe.SecretKey, len(shares))
	roundTwo := make([]multiparty.RelinearizationKeyGenShare, len(shares))
	_, combinedOne, combinedTwo := protocol.AllocateShare()

	for i, secretKeyShare := range shares {
		var roundOne multiparty.RelinearizationKeyGenShare
		eph[i], roundOne, roundTwo[i] = protocol.AllocateShare()
		protocol.GenShareRoundOne(secretKeyShare, crp, eph[i], &roundOne)
		protocol.AggregateShares(roundOne, combinedOne, &combinedOne)
	}
	for i, secretKeyShare := range shares {
		protocol.GenShareRoundTwo(eph[i], secretKeyShare, combinedOne, &roundTwo[i])
		protocol.AggregateShares(roundTwo[i], combinedTwo, &combinedTwo)
	}

	relinKey := rlwe.NewRelinearizationKey(params)
	protocol.GenRelinearizationKey(combinedOne, combinedTwo, relinKey)
	return relinKey
}

func generateGaloisKeys(
	params bgv.Parameters,
	shares []*rlwe.SecretKey,
	crs multiparty.CRS,
	elements []uint64,
) ([]*rlwe.GaloisKey, error) {
	protocol := multiparty.NewGaloisKeyGenProtocol(params)
	keys := make([]*rlwe.GaloisKey, len(elements))
	for keyIndex, element := range elements {
		crp := protocol.SampleCRP(crs)
		combined := protocol.AllocateShare()
		combined.GaloisElement = element
		for _, secretKeyShare := range shares {
			share := protocol.AllocateShare()
			if err := protocol.GenShare(secretKeyShare, element, crp, &share); err != nil {
				return nil, err
			}
			if err := protocol.AggregateShares(share, combined, &combined); err != nil {
				return nil, err
			}
		}
		keys[keyIndex] = rlwe.NewGaloisKey(params)
		if err := protocol.GenGaloisKey(combined, crp, keys[keyIndex]); err != nil {
			return nil, err
		}
	}
	return keys, nil
}

// PartialDecrypt performs one sender's local share generation for every
// routing output ciphertext.
// PARALLELIZED
func (s *Sender) PartialDecrypt(
	output Output,
	noise ring.DistributionParameters,
) (PartialDecryption, error) {
	zero := rlwe.NewSecretKey(s.params)

	partial := PartialDecryption{
		Payloads: make(
			[]multiparty.KeySwitchShare,
			len(output.Payloads),
		),
	}

	// Generate the header share serially.
	headerProtocol, err := multiparty.NewKeySwitchProtocol(
		s.params,
		noise,
	)
	if err != nil {
		return PartialDecryption{}, err
	}

	partial.Header = headerProtocol.AllocateShare(
		output.Header.Level(),
	)

	headerProtocol.GenShare(
		s.Share,
		zero,
		output.Header,
		&partial.Header,
	)

	// Generate payload shares in parallel.
	workerCount := min(
		runtime.GOMAXPROCS(0),
		len(output.Payloads),
	)

	var wg sync.WaitGroup
	var errOnce sync.Once
	var firstErr error

	for worker := 0; worker < workerCount; worker++ {
		start := worker * len(output.Payloads) / workerCount
		end := (worker + 1) * len(output.Payloads) / workerCount

		wg.Add(1)

		go func(start, end int) {
			defer wg.Done()

			// Each worker gets its own protocol and therefore its own
			// noise sampler.
			protocol, err := multiparty.NewKeySwitchProtocol(
				s.params,
				noise,
			)
			if err != nil {
				errOnce.Do(func() {
					firstErr = err
				})
				return
			}

			for moment := start; moment < end; moment++ {
				ciphertext := output.Payloads[moment]

				partial.Payloads[moment] = protocol.AllocateShare(
					ciphertext.Level(),
				)

				protocol.GenShare(
					s.Share,
					zero,
					ciphertext,
					&partial.Payloads[moment],
				)
			}
		}(start, end)
	}

	wg.Wait()

	if firstErr != nil {
		return PartialDecryption{}, firstErr
	}

	return partial, nil
}

// complete router output.
func (r *Router) AggregatePartialDecryptions(
	output Output,
	partials []PartialDecryption,
	noise ring.DistributionParameters,
) (OpenedOutput, error) {
	if len(partials) != r.layout.n || len(output.Payloads) != r.layout.n {
		return OpenedOutput{}, fmt.Errorf(
			"opening requires n=%d outputs and sender shares",
			r.layout.n,
		)
	}

	// Header: do serially.
	headerProtocol, err := multiparty.NewKeySwitchProtocol(
		r.params,
		noise,
	)
	if err != nil {
		return OpenedOutput{}, err
	}

	headerShares := make([]multiparty.KeySwitchShare, len(partials))
	for sender := range partials {
		headerShares[sender] = partials[sender].Header
	}

	header, err := r.aggregateAndDecrypt(
		headerProtocol,
		r.encoder,
		r.decryptor,
		output.Header,
		headerShares,
	)
	if err != nil {
		return OpenedOutput{}, err
	}

	// Payloads: parallelize across moments.
	payloads := make([][]uint64, len(output.Payloads))

	workerCount := min(runtime.GOMAXPROCS(0), len(output.Payloads))

	var wg sync.WaitGroup
	var errOnce sync.Once
	var firstErr error

	for worker := 0; worker < workerCount; worker++ {
		start := worker * len(output.Payloads) / workerCount
		end := (worker + 1) * len(output.Payloads) / workerCount

		wg.Add(1)

		go func(start, end int) {
			defer wg.Done()

			protocol, err := multiparty.NewKeySwitchProtocol(
				r.params,
				noise,
			)
			if err != nil {
				errOnce.Do(func() {
					firstErr = err
				})
				return
			}

			encoder := bgv.NewEncoder(r.params)
			zero := rlwe.NewSecretKey(r.params)
			decryptor := bgv.NewDecryptor(r.params, zero)

			shares := make([]multiparty.KeySwitchShare, len(partials))

			for moment := start; moment < end; moment++ {
				for sender := range partials {
					shares[sender] = partials[sender].Payloads[moment]
				}

				values, err := r.aggregateAndDecrypt(
					protocol,
					encoder,
					decryptor,
					output.Payloads[moment],
					shares,
				)
				if err != nil {
					errOnce.Do(func() {
						firstErr = err
					})
					return
				}

				payloads[moment] = values
			}
		}(start, end)
	}

	wg.Wait()

	if firstErr != nil {
		return OpenedOutput{}, firstErr
	}

	return OpenedOutput{
		Header:   header,
		Payloads: payloads,
	}, nil
}

func (r *Router) aggregateAndDecrypt(
	protocol multiparty.KeySwitchProtocol,
	encoder *bgv.Encoder,
	decryptor *rlwe.Decryptor,
	ciphertext *rlwe.Ciphertext,
	shares []multiparty.KeySwitchShare,
) ([]uint64, error) {
	combined := protocol.AllocateShare(ciphertext.Level())

	for _, share := range shares {
		if err := protocol.AggregateShares(
			share,
			combined,
			&combined,
		); err != nil {
			return nil, err
		}
	}

	switched := bgv.NewCiphertext(
		r.params,
		1,
		ciphertext.Level(),
	)

	protocol.KeySwitch(
		ciphertext,
		combined,
		switched,
	)

	return Decrypt(
		r.params,
		encoder,
		decryptor,
		switched,
	)
}
