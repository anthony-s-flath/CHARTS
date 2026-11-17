package charts

import (
	"math/big"
	"math/rand"
	"testing"
)

func TestFieldArithmeticAgainstBigIntegers(t *testing.T) {
	field := newPrimeField(PaperPlaintextModulus)
	rng := rand.New(rand.NewSource(1))

	for iteration := 0; iteration < 256; iteration++ {
		a := rng.Uint64() % field.modulus
		b := rng.Uint64() % field.modulus

		if have, want := field.add(a, b), bigBinary(a, b, field.modulus, new(big.Int).Add); have != want {
			t.Fatalf("add(%d,%d)=%d; want %d", a, b, have, want)
		}
		if have, want := field.sub(a, b), bigBinary(a, b, field.modulus, new(big.Int).Sub); have != want {
			t.Fatalf("sub(%d,%d)=%d; want %d", a, b, have, want)
		}
		if have, want := field.mul(a, b), bigBinary(a, b, field.modulus, new(big.Int).Mul); have != want {
			t.Fatalf("mul(%d,%d)=%d; want %d", a, b, have, want)
		}
	}
}

func TestFieldInverse(t *testing.T) {
	field := newPrimeField(PaperPlaintextModulus)
	for _, value := range []uint64{1, 2, 3, 17, field.modulus - 1} {
		inverse := inverseMod(value, field.modulus)
		if product := field.mul(value, inverse); product != 1 {
			t.Fatalf("%d * inverse(%d) = %d; want 1", value, value, product)
		}
	}
}

func bigBinary(
	a uint64,
	b uint64,
	modulus uint64,
	operation func(x, y *big.Int) *big.Int,
) uint64 {
	result := operation(
		new(big.Int).SetUint64(a),
		new(big.Int).SetUint64(b),
	)
	result.Mod(result, new(big.Int).SetUint64(modulus))
	return result.Uint64()
}
