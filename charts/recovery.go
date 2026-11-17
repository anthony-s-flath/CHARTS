package charts

import (
	"fmt"
	"math/bits"
	"runtime"
	"sync"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

// OpenedOutput is the coefficient-decoded form of Output.
type OpenedOutput struct {
	Header   []uint64
	Payloads [][]uint64
}

// Message is a recovered tag and message polynomial.
type Message struct {
	Tag          uint64
	Coefficients []uint64
}

// Open applies a caller-supplied ordinary opener to every output ciphertext.
// The collective path is Sender.PartialDecrypt followed by
// Router.AggregatePartialDecryptions.
func Open(
	output Output,
	opener func(*rlwe.Ciphertext) ([]uint64, error),
) (OpenedOutput, error) {
	header, err := opener(output.Header)
	if err != nil {
		return OpenedOutput{}, err
	}

	payloads := make([][]uint64, len(output.Payloads))
	for moment := range output.Payloads {
		payloads[moment], err = opener(output.Payloads[moment])
		if err != nil {
			return OpenedOutput{}, err
		}
	}

	return OpenedOutput{Header: header, Payloads: payloads}, nil
}

// Decrypt returns the coefficient encoding of ct. It is used after ordinary
// secret-key decryption or collective key switching.
func Decrypt(
	params bgv.Parameters,
	encoder *bgv.Encoder,
	decryptor *rlwe.Decryptor,
	ciphertext *rlwe.Ciphertext,
) ([]uint64, error) {
	plaintext := bgv.NewPlaintext(params, ciphertext.Level())
	decryptor.Decrypt(ciphertext, plaintext)
	values := make([]uint64, params.N())
	if err := encoder.Decode(plaintext, values); err != nil {
		return nil, err
	}
	return values, nil
}

// Decode recovers the tags and all N coefficients of every message.
func Decode(
	output OpenedOutput,
	params bgv.Parameters,
) ([]Message, error) {
	n := len(output.Payloads)
	messageLength := params.N()
	for _, payload := range output.Payloads {
		if len(payload) != messageLength {
			return nil, fmt.Errorf("payloads must contain N=%d coefficients", messageLength)
		}
	}

	field := newPrimeField(params.PlaintextModulus())
	locator, err := tagPolynomial(output.Header, n, field)
	if err != nil {
		return nil, err
	}
	tags, err := roots(locator, field)
	if err != nil {
		return nil, err
	}

	messages := make([]Message, n)

	workerCount := min(
		runtime.GOMAXPROCS(0),
		len(tags),
	)

	var wg sync.WaitGroup

	for worker := 0; worker < workerCount; worker++ {
		start := worker * len(tags) / workerCount
		end := (worker + 1) * len(tags) / workerCount

		wg.Add(1)

		go func(start, end int) {
			defer wg.Done()

			for message := start; message < end; message++ {
				tag := tags[message]

				weights := inverseVandermondeRow(
					locator,
					tag,
					field,
				)

				messages[message] = Message{
					Tag: tag,
					Coefficients: recoverCoefficients(
						weights,
						output.Payloads,
						messageLength,
						field.modulus,
					),
				}
			}
		}(start, end)
	}

	wg.Wait()

	return messages, nil
}

// recoverCoefficients accumulates each dot product in 128 bits and reduces it
// once, avoiding one modular reduction for every entry of the n-by-n-by-N
// product.
func recoverCoefficients(
	weights []uint64,
	payloads [][]uint64,
	messageLength int,
	modulus uint64,
) []uint64 {
	low := make([]uint64, messageLength)
	high := make([]uint64, messageLength)
	for moment, weight := range weights {
		for coefficient, value := range payloads[moment] {
			productHigh, productLow := bits.Mul64(weight, value)
			var carry uint64
			low[coefficient], carry = bits.Add64(
				low[coefficient],
				productLow,
				0,
			)
			high[coefficient] += productHigh + carry
		}
	}
	for coefficient := range low {
		_, low[coefficient] = bits.Div64(
			high[coefficient],
			low[coefficient],
			modulus,
		)
	}
	return low
}

// DecodeTags recovers only the n tags from an opened header.
func DecodeTags(
	header []uint64,
	n int,
	modulus uint64,
) ([]uint64, error) {
	field := newPrimeField(modulus)
	locator, err := tagPolynomial(header, n, field)
	if err != nil {
		return nil, err
	}
	return roots(locator, field)
}

func tagPolynomial(
	header []uint64,
	n int,
	field primeField,
) ([]uint64, error) {
	if len(header) < n+1 {
		return nil, fmt.Errorf("header must contain H_0 through H_%d", n)
	}
	if header[0] != uint64(n) {
		return nil, fmt.Errorf("H_0=%d; want n=%d", header[0], n)
	}

	elementary := newtonIdentities(header[1:n+1], field)
	locator := make([]uint64, n+1)
	locator[n] = 1
	for k := 1; k <= n; k++ {
		locator[n-k] = elementary[k]
		if k&1 == 1 && locator[n-k] != 0 {
			locator[n-k] = field.modulus - locator[n-k]
		}
	}
	return locator, nil
}

// newtonIdentities converts H_1,...,H_n into e_0,...,e_n.
func newtonIdentities(powerSums []uint64, field primeField) []uint64 {
	elementary := make([]uint64, len(powerSums)+1)
	elementary[0] = 1
	for k := 1; k < len(elementary); k++ {
		for j := 1; j <= k; j++ {
			term := field.mul(elementary[k-j], powerSums[j-1])
			if j&1 == 1 {
				elementary[k] = field.add(elementary[k], term)
			} else {
				elementary[k] = field.sub(elementary[k], term)
			}
		}
		elementary[k] = field.mul(
			elementary[k],
			inverseMod(uint64(k), field.modulus),
		)
	}
	return elementary
}

// inverseVandermondeRow returns the coefficients of a polynomial that is one
// at tag and zero at every other recovered tag. These coefficients are the
// required row of V^{-1}, without constructing or inverting V.
func inverseVandermondeRow(
	locator []uint64,
	tag uint64,
	field primeField,
) []uint64 {
	degree := len(locator) - 1
	weights := make([]uint64, degree)
	weights[degree-1] = locator[degree]
	for coefficient := degree - 2; coefficient >= 0; coefficient-- {
		weights[coefficient] = field.add(
			locator[coefficient+1],
			field.mul(tag, weights[coefficient+1]),
		)
	}

	denominator := ring.EvalPolyModP(tag, weights, field.modulus)
	scale := inverseMod(denominator, field.modulus)
	for coefficient := range weights {
		weights[coefficient] = field.mul(weights[coefficient], scale)
	}
	return weights
}
