package charts

import (
	"fmt"
	"math/bits"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

// TestExpandSparseMatchesLattigo verifies that ExpandSparse has the same
// plaintext output as Lattigo's generic RingPackingEvaluator.Expand for every
// (n, b) combination used by CHARTS.
//
// The test intentionally uses a small ring degree so that it remains a fast
// unit test. Expansion depends only on the power-of-two relationship among N,
// L, and gap, so the same branching structure is exercised as with CHARTS's
// larger production parameters.
func TestExpandSparseMatchesLattigo(t *testing.T) {
	t.Parallel()

	tc := bgv.NewTestContext(bgv.ParametersLiteral{
		LogN:             8, // N = 256; large enough for every tested n.
		LogQ:             []int{55, 52},
		LogP:             []int{55},
		PlaintextModulus: 65537,
	}, false)

	params := tc.Params
	logN := params.LogN()
	N := params.N()

	// GenExtractEvaluationKeys populates ExtractKeys but not Parameters, so the
	// full-ring parameter entry must be supplied explicitly.
	packingKeys := &rlwe.RingPackingEvaluationKey{
		Parameters: map[int]rlwe.ParameterProvider{
			logN: params,
		},
	}
	packingKeys.GenExtractEvaluationKeys(
		params,
		tc.Sk,
		rlwe.EvaluationKeyParameters{},
	)

	packing := rlwe.NewRingPackingEvaluator(packingKeys)

	testCases := []struct {
		n int
		b int
	}{
		{n: 32, b: 4},
		{n: 32, b: 16},
		{n: 64, b: 4},
		{n: 64, b: 16},
		{n: 128, b: 4},
		{n: 128, b: 16},
	}

	for _, testCase := range testCases {
		testCase := testCase

		t.Run(fmt.Sprintf("n=%d/b=%d", testCase.n, testCase.b), func(t *testing.T) {
			if testCase.n%testCase.b != 0 {
				t.Fatalf("n=%d is not divisible by b=%d", testCase.n, testCase.b)
			}

			L := testCase.n / testCase.b
			if L&(L-1) != 0 {
				t.Fatalf("L=%d is not a power of two", L)
			}

			if N%L != 0 {
				t.Fatalf("N=%d is not divisible by L=%d", N, L)
			}

			gap := N / L
			if gap&(gap-1) != 0 {
				t.Fatalf("gap=%d is not a power of two", gap)
			}

			logGap := bits.TrailingZeros(uint(gap))

			// Construct a coefficient-encoded plaintext supported only at
			// 0, gap, 2*gap, ..., (L-1)*gap.
			wantControl := make([]uint64, N)
			for s := 0; s < L; s++ {
				wantControl[s*gap] = uint64((s + 1) * (s + 2))
			}

			controlPlaintext := bgv.NewPlaintext(params, params.MaxLevel())
			controlPlaintext.IsBatched = false
			require.NoError(t, tc.Ecd.Encode(wantControl, controlPlaintext))

			controlCiphertext, err := tc.Enc.EncryptNew(controlPlaintext)
			require.NoError(t, err)

			generic, err := packing.Expand(controlCiphertext, logGap)
			require.NoError(t, err)

			sparse, err := ExpandSparse(packing, controlCiphertext, logGap)
			require.NoError(t, err)

			require.Len(t, generic, L)
			require.Len(t, sparse, L)

			for s := 0; s < L; s++ {
				index := s * gap

				genericCiphertext, ok := generic[index]
				require.True(t, ok, "generic expansion is missing index %d", index)

				sparseCiphertext, ok := sparse[index]
				require.True(t, ok, "sparse expansion is missing index %d", index)

				wantExpanded := make([]uint64, N)
				wantExpanded[0] = wantControl[index]

				genericDecoded := decodeCoefficientCiphertext(
					t,
					tc,
					genericCiphertext,
				)
				sparseDecoded := decodeCoefficientCiphertext(
					t,
					tc,
					sparseCiphertext,
				)

				require.Equal(t, wantExpanded, genericDecoded)
				require.Equal(t, wantExpanded, sparseDecoded)
				require.Equal(t, genericDecoded, sparseDecoded)
			}
		})
	}
}

func decodeCoefficientCiphertext(
	t *testing.T,
	tc *bgv.TestContext,
	ct *rlwe.Ciphertext,
) []uint64 {
	t.Helper()

	decoded := make([]uint64, tc.Params.N())
	plaintext := tc.Dec.DecryptNew(ct)
	require.NoError(t, tc.Ecd.Decode(plaintext, decoded))

	return decoded
}

func TestExpandSparseRejectsInvalidLogGap(t *testing.T) {
	t.Parallel()

	tc := bgv.NewTestContext(bgv.ParametersLiteral{
		LogN:             4,
		LogQ:             []int{40},
		LogP:             []int{40},
		PlaintextModulus: 257,
	}, false)

	params := tc.Params
	packingKeys := &rlwe.RingPackingEvaluationKey{
		Parameters: map[int]rlwe.ParameterProvider{
			params.LogN(): params,
		},
	}
	packingKeys.GenExtractEvaluationKeys(
		params,
		tc.Sk,
		rlwe.EvaluationKeyParameters{},
	)

	packing := rlwe.NewRingPackingEvaluator(packingKeys)
	plaintext := bgv.NewPlaintext(params, params.MaxLevel())
	plaintext.IsBatched = false
	require.NoError(t, tc.Ecd.Encode(make([]uint64, params.N()), plaintext))

	ciphertext, err := tc.Enc.EncryptNew(plaintext)
	require.NoError(t, err)

	_, err = ExpandSparse(packing, ciphertext, -1)
	require.Error(t, err)

	_, err = ExpandSparse(packing, ciphertext, params.LogN()+1)
	require.Error(t, err)
}
