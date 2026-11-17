// Pdckage charts implements the n-sender CHARTS routing construction with
// coefficient-encoded BGV ciphertexts.
package charts

import (
	"fmt"
	"strings"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

const (
	TrivialPlaintextModulus     uint64 = 65_537
	PaperPlaintextModulus       uint64 = 9_007_199_255_019_521
	PaperN                             = 256
	PaperB                             = 256
	DefaultSmudgingSecurityBits        = 146
	DefaultLog2RoutedNoise             = 18 // std dev
	OptimizedLog2RoutedNoise           = 88 // std dev
	TrivialN                           = 8
	TrivialB                           = 2
)

func paperParameterLiteralOptimization() bgv.ParametersLiteral {
	return bgv.ParametersLiteral{
		LogN:             14,
		LogQ:             []int{60, 60, 55, 55},
		LogP:             []int{60},
		PlaintextModulus: PaperPlaintextModulus,
	}
}

func paperParameterLiteral() bgv.ParametersLiteral {
	return bgv.ParametersLiteral{
		LogN:             13,
		LogQ:             []int{54, 50, 50},
		PlaintextModulus: PaperPlaintextModulus,
	}
}

// TrivialParameters are intentionally small and insecure.
func TrivialParameters() (bgv.Parameters, error) {
	return bgv.NewParametersFromLiteral(trivialParameterLiteral())
}

func trivialParameterLiteral() bgv.ParametersLiteral {
	return bgv.ParametersLiteral{
		LogN:             8,
		LogQ:             []int{55, 52, 52},
		LogP:             []int{51, 51},
		PlaintextModulus: TrivialPlaintextModulus,
	}
}

// ParameterLiteralForRouting selects the paper preset from the routing circuit.
// Explicit experiment overrides are applied to this literal by the config loader.
func ParameterLiteralForRouting(profile string, n, b int) (bgv.ParametersLiteral, error) {
	if strings.EqualFold(profile, "paper") && b != n {
		return paperParameterLiteralOptimization(), nil
	}
	switch strings.ToLower(profile) {
	case "trivial":
		return trivialParameterLiteral(), nil
	case "paper":
		return paperParameterLiteral(), nil
	default:
		return bgv.ParametersLiteral{}, fmt.Errorf("unknown parameter profile %q; use trivial or paper", profile)
	}
}

// galoisElements returns only the automorphisms used by CHARTS's sparse
// coefficient expansion.
func galoisElements(
	params bgv.Parameters,
	n int,
	b int,
) ([]uint64, error) {
	layout, err := newRoutingLayout(params, n, b)
	if err != nil {
		return nil, err
	}
	if layout.factorCount == 1 {
		return nil, nil
	}

	all := rlwe.GaloisElementsForExpand(params, params.LogN())
	return append([]uint64(nil), all[layout.logCoefficientGap:]...), nil
}

func DefaultLog2RoutedNoiseForRouting(n, b int) int {
	if b != n {
		return OptimizedLog2RoutedNoise
	}
	return DefaultLog2RoutedNoise
}
