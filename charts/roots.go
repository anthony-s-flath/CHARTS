package charts

import (
	"fmt"
	"math/rand"
	"slices"
)

// roots factors the tag polynomial into distinct roots.
func roots(polynomial []uint64, field primeField) ([]uint64, error) {
	f := polynomialMonic(polynomial, field)
	degree := polynomialDegree(f)
	if degree < 1 {
		return nil, fmt.Errorf("tag polynomial is constant")
	}
	if polynomialDegree(polynomialGCD(
		f,
		polynomialDerivative(f, field),
		field,
	)) != 0 {
		return nil, fmt.Errorf("tags are not distinct")
	}

	rng := rand.New(rand.NewSource(int64(polynomialSeed(f, field.modulus))))
	result := make([]uint64, 0, degree)
	if err := splitLinearFactors(f, field, rng, &result); err != nil {
		return nil, err
	}

	// assign ordering
	slices.Sort(result)
	return result, nil
}

// splitLinearFactors recursively splits f until every factor is linear.
func splitLinearFactors(
	f []uint64,
	field primeField,
	rng *rand.Rand,
	result *[]uint64,
) error {
	degree := polynomialDegree(f)
	if degree == 1 {
		*result = append(*result, field.sub(0, f[0]))
		return nil
	}

	for attempt := 0; attempt < 64; attempt++ {
		randomPolynomial := make([]uint64, degree)
		for i := range randomPolynomial {
			randomPolynomial[i] = rng.Uint64() % field.modulus
		}

		// Euler's criterion partitions the roots by quadratic character.
		residue := polynomialPowMod(
			randomPolynomial,
			(field.modulus-1)/2,
			f,
			field,
		)
		if len(residue) == 0 {
			residue = []uint64{field.modulus - 1}
		} else {
			residue[0] = field.sub(residue[0], 1)
		}

		factor := polynomialGCD(residue, f, field)
		factorDegree := polynomialDegree(factor)
		if factorDegree <= 0 || factorDegree == degree {
			continue
		}

		quotient, _ := polynomialDivMod(f, factor, field)
		if err := splitLinearFactors(
			factor,
			field,
			rng,
			result,
		); err != nil {
			return err
		}
		return splitLinearFactors(
			quotient,
			field,
			rng,
			result,
		)
	}

	return fmt.Errorf("tag polynomial does not split over the plaintext field")
}

// polynomialDegree returns -1 for the zero polynomial.
func polynomialDegree(polynomial []uint64) int {
	for degree := len(polynomial) - 1; degree >= 0; degree-- {
		if polynomial[degree] != 0 {
			return degree
		}
	}
	return -1
}

// polynomialTrim removes trailing zero coefficients without copying.
func polynomialTrim(polynomial []uint64) []uint64 {
	degree := polynomialDegree(polynomial)
	if degree < 0 {
		return nil
	}
	return polynomial[:degree+1]
}

// polynomialMonic reduces coefficients and scales the leading term to one.
func polynomialMonic(polynomial []uint64, field primeField) []uint64 {
	result := append([]uint64(nil), polynomial...)
	for i := range result {
		if result[i] >= field.modulus {
			result[i] %= field.modulus
		}
	}
	result = polynomialTrim(result)
	if len(result) == 0 {
		return nil
	}

	leading := result[len(result)-1]
	if leading != 1 {
		scale := inverseMod(leading, field.modulus)
		for i := range result {
			result[i] = field.mul(result[i], scale)
		}
	}
	return result
}

// polynomialDerivative computes the formal derivative over the field.
func polynomialDerivative(polynomial []uint64, field primeField) []uint64 {
	if len(polynomial) <= 1 {
		return nil
	}
	result := make([]uint64, len(polynomial)-1)
	for degree := 1; degree < len(polynomial); degree++ {
		result[degree-1] = field.mul(uint64(degree), polynomial[degree])
	}
	return polynomialTrim(result)
}

// polynomialGCD uses the Euclidean algorithm and returns a monic result.
func polynomialGCD(a, b []uint64, field primeField) []uint64 {
	a = polynomialTrim(a)
	b = polynomialTrim(b)
	for len(b) != 0 {
		a, b = b, polynomialRemainder(a, b, field)
	}
	return polynomialMonic(a, field)
}

// polynomialDivMod returns quotient and remainder from polynomial division.
func polynomialDivMod(
	dividend, divisor []uint64,
	field primeField,
) ([]uint64, []uint64) {
	dividendDegree := polynomialDegree(dividend)
	divisorDegree := polynomialDegree(divisor)
	if divisorDegree < 0 {
		panic("polynomial division by zero")
	}
	if dividendDegree < divisorDegree {
		return nil, append([]uint64(nil), dividend...)
	}

	quotient := make([]uint64, dividendDegree-divisorDegree+1)
	remainder := reducePolynomial(dividend, divisor, quotient, field)
	return polynomialTrim(quotient), remainder
}

// polynomialRemainder computes dividend modulo divisor without a quotient.
func polynomialRemainder(
	dividend, divisor []uint64,
	field primeField,
) []uint64 {
	if polynomialDegree(dividend) < polynomialDegree(divisor) {
		return append([]uint64(nil), dividend...)
	}
	return reducePolynomial(dividend, divisor, nil, field)
}

// reducePolynomial divides dividend by divisor. When quotient is nil it skips
// quotient construction, which is the common modular-arithmetic path.
func reducePolynomial(
	dividend, divisor, quotient []uint64,
	field primeField,
) []uint64 {
	remainder := append([]uint64(nil), dividend...)
	divisorDegree := polynomialDegree(divisor)
	remainderDegree := polynomialDegree(remainder)
	leadingInverse := uint64(1)
	if divisor[divisorDegree] != 1 {
		leadingInverse = inverseMod(divisor[divisorDegree], field.modulus)
	}

	for remainderDegree >= divisorDegree {
		shift := remainderDegree - divisorDegree
		coefficient := field.mul(
			remainder[remainderDegree],
			leadingInverse,
		)
		if quotient != nil {
			quotient[shift] = coefficient
		}
		for i := 0; i <= divisorDegree; i++ {
			remainder[i+shift] = field.sub(
				remainder[i+shift],
				field.mul(coefficient, divisor[i]),
			)
		}
		for remainderDegree >= 0 && remainder[remainderDegree] == 0 {
			remainderDegree--
		}
	}
	if remainderDegree < 0 {
		return nil
	}
	return remainder[:remainderDegree+1]
}

// polynomialMulMod multiplies a and b modulo divisor.
func polynomialMulMod(
	a, b, divisor []uint64,
	field primeField,
) []uint64 {
	if len(a) == 0 || len(b) == 0 {
		return nil
	}
	product := make([]uint64, len(a)+len(b)-1)
	for i, left := range a {
		for j, right := range b {
			product[i+j] = field.add(
				product[i+j],
				field.mul(left, right),
			)
		}
	}
	return polynomialRemainder(product, divisor, field)
}

// polynomialPowMod uses square-and-multiply modulo divisor.
func polynomialPowMod(
	base []uint64,
	exponent uint64,
	divisor []uint64,
	field primeField,
) []uint64 {
	result := []uint64{1}
	base = polynomialRemainder(base, divisor, field)
	for exponent != 0 {
		if exponent&1 == 1 {
			result = polynomialMulMod(result, base, divisor, field)
		}
		exponent >>= 1
		if exponent != 0 {
			base = polynomialMulMod(base, base, divisor, field)
		}
	}
	return polynomialTrim(result)
}

// polynomialSeed makes the randomized splitting reproducible for each input.
func polynomialSeed(polynomial []uint64, modulus uint64) uint64 {
	const (
		offset = uint64(1469598103934665603)
		prime  = uint64(1099511628211)
	)
	seed := (offset ^ modulus) * prime
	for _, coefficient := range polynomial {
		seed = (seed ^ coefficient) * prime
	}
	return seed
}
