// Package testutil provides centralized-key test fixtures.
package testutil

import (
	"fmt"
	"math/bits"

	charts "github.com/anthony-s-flath/CHARTS/charts"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

type Context struct {
	Params     bgv.Parameters
	Encoder    *bgv.Encoder
	SecretKey  *rlwe.SecretKey
	PublicKey  *rlwe.PublicKey
	RelinKey   *rlwe.RelinearizationKey
	GaloisKeys []*rlwe.GaloisKey
	Decryptor  *rlwe.Decryptor
	Evaluator  *bgv.Evaluator
	encryptor  *rlwe.Encryptor
}

// New builds a fixture with all expansion keys for isolated expansion tests.
func New(params bgv.Parameters) *Context {
	return newContext(params, true, rlwe.GaloisElementsForExpand(params, params.LogN()))
}

// NewForRouting allocates only keys needed by the already-validated circuit.
func NewForRouting(params bgv.Parameters, n, b int) *Context {
	if n == b {
		return newContext(params, false, nil)
	}
	logGap := params.LogN() - (bits.Len(uint(n/b)) - 1)
	elements := rlwe.GaloisElementsForExpand(params, params.LogN())[logGap:]
	return newContext(params, true, elements)
}

func newContext(params bgv.Parameters, needsRelin bool, elements []uint64) *Context {
	keyGenerator := rlwe.NewKeyGenerator(params)
	secretKey, publicKey := keyGenerator.GenKeyPairNew()
	var relinKey *rlwe.RelinearizationKey
	if needsRelin {
		relinKey = keyGenerator.GenRelinearizationKeyNew(secretKey)
	}
	galoisKeys := keyGenerator.GenGaloisKeysNew(
		elements,
		secretKey,
	)
	return &Context{
		Params:     params,
		Encoder:    bgv.NewEncoder(params),
		SecretKey:  secretKey,
		PublicKey:  publicKey,
		RelinKey:   relinKey,
		GaloisKeys: galoisKeys,
		Decryptor:  bgv.NewDecryptor(params, secretKey),
		Evaluator: bgv.NewEvaluator(
			params,
			rlwe.NewMemEvaluationKeySet(relinKey, galoisKeys...),
			true,
		),
		encryptor: bgv.NewEncryptor(params, publicKey),
	}
}

func (c *Context) Encrypt(values []uint64) (*rlwe.Ciphertext, error) {
	plaintext := bgv.NewPlaintext(c.Params, c.Params.MaxLevel())
	plaintext.IsBatched = false
	if err := c.Encoder.Encode(values, plaintext); err != nil {
		return nil, err
	}
	return c.encryptor.EncryptNew(plaintext)
}

func (c *Context) Decrypt(ciphertext *rlwe.Ciphertext) ([]uint64, error) {
	return charts.Decrypt(c.Params, c.Encoder, c.Decryptor, ciphertext)
}

func EqualPrefix(have, want []uint64) error {
	if len(have) < len(want) {
		return fmt.Errorf("have %d coefficients; want at least %d", len(have), len(want))
	}
	for i := range want {
		if have[i] != want[i] {
			return fmt.Errorf("coefficient %d: have %d, want %d", i, have[i], want[i])
		}
	}
	return nil
}
