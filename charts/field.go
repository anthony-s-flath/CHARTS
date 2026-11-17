package charts

import (
	"math/big"

	"github.com/tuneinsight/lattigo/v6/ring"
)

// primeField stores the constant used by every plaintext-field multiplication.
// Recovery performs millions of these operations, so using
// Lattigo's reduction avoids a hardware division for each one.
type primeField struct {
	modulus   uint64
	reduction [2]uint64
}

func newPrimeField(modulus uint64) primeField {
	return primeField{
		modulus:   modulus,
		reduction: ring.GenBRedConstant(modulus),
	}
}

func (f primeField) add(a, b uint64) uint64 {
	return ring.CRed(a+b, f.modulus)
}

func (f primeField) sub(a, b uint64) uint64 {
	if a >= b {
		return a - b
	}
	return a + f.modulus - b
}

func (f primeField) mul(a, b uint64) uint64 {
	return ring.BRed(a, b, f.modulus, f.reduction)
}

// adapts modular inverse to uint64 field elements.
func inverseMod(value, modulus uint64) uint64 {
	return new(big.Int).ModInverse(
		new(big.Int).SetUint64(value),
		new(big.Int).SetUint64(modulus),
	).Uint64()
}
