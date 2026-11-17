package charts

import (
	"github.com/tuneinsight/lattigo/v6/ring"
	"slices"
	"testing"
)

func TestRootsRecoversDistinctFieldElements(t *testing.T) {
	field := newPrimeField(PaperPlaintextModulus)
	want := []uint64{
		0,
		3,
		5,
		7,
		11,
		101,
		1_000_003,
		123_456_789,
		PaperPlaintextModulus - 2,
	}
	polynomial := polynomialFromRoots(want, field)

	have, err := roots(polynomial, field)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(have, want) {
		t.Fatalf("roots=%v; want %v", have, want)
	}
	for _, root := range have {
		if value := evaluatePolynomial(polynomial, root, field); value != 0 {
			t.Fatalf("f(%d)=%d; want 0", root, value)
		}
	}
}

func TestRootsRejectsMalformedLocators(t *testing.T) {
	field := newPrimeField(PaperPlaintextModulus)
	// A nonsplitting quadratic must use a non-residue of this exact field.
	c := uint64(2)
	for ring.ModExp(c, (field.modulus-1)/2, field.modulus) != field.modulus-1 {
		c++
	}
	tests := []struct {
		name       string
		polynomial []uint64
	}{
		{
			name:       "constant",
			polynomial: []uint64{1},
		},
		{
			name: "repeated root",
			polynomial: polynomialFromRoots(
				[]uint64{7, 7},
				field,
			),
		},
		{
			name:       "does not split",
			polynomial: []uint64{field.modulus - c, 0, 1},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := roots(test.polynomial, field); err == nil {
				t.Fatal("roots accepted malformed locator")
			}
		})
	}
}

func TestPolynomialDivisionReconstructsDividend(t *testing.T) {
	field := newPrimeField(PaperPlaintextModulus)
	divisor := polynomialFromRoots(
		[]uint64{3, 11},
		field,
	)
	quotientWant := polynomialFromRoots(
		[]uint64{17, 29, 41},
		field,
	)
	dividend := polynomialProduct(
		divisor,
		quotientWant,
		field,
	)

	quotient, remainder := polynomialDivMod(
		dividend,
		divisor,
		field,
	)
	if polynomialDegree(remainder) >= 0 {
		t.Fatalf("remainder=%v; want zero", remainder)
	}
	if !slices.Equal(quotient, quotientWant) {
		t.Fatalf("quotient=%v; want %v", quotient, quotientWant)
	}
}

func polynomialFromRoots(fieldRoots []uint64, field primeField) []uint64 {
	polynomial := []uint64{1}
	for _, root := range fieldRoots {
		next := make([]uint64, len(polynomial)+1)
		for degree, coefficient := range polynomial {
			next[degree] = field.sub(
				next[degree],
				field.mul(coefficient, root),
			)
			next[degree+1] = field.add(
				next[degree+1],
				coefficient,
			)
		}
		polynomial = next
	}
	return polynomial
}

func polynomialProduct(a, b []uint64, field primeField) []uint64 {
	product := make([]uint64, len(a)+len(b)-1)
	for i, left := range a {
		for j, right := range b {
			product[i+j] = field.add(
				product[i+j],
				field.mul(left, right),
			)
		}
	}
	return polynomialTrim(product)
}

func evaluatePolynomial(
	polynomial []uint64,
	value uint64,
	field primeField,
) uint64 {
	result := uint64(0)
	for degree := len(polynomial) - 1; degree >= 0; degree-- {
		result = field.add(
			field.mul(result, value),
			polynomial[degree],
		)
	}
	return result
}
