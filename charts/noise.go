package charts

import (
	"math"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

// Noise reports the residual after subtracting the expected plaintext. The
// fields are base-2 logarithms; Budget is empirical headroom to Q/2.
type Noise struct {
	Std    float64
	MinAbs float64
	MaxAbs float64
	Budget float64
}

func MeasureNoise(
	params bgv.Parameters,
	encoder *bgv.Encoder,
	decryptor *rlwe.Decryptor,
	ciphertext *rlwe.Ciphertext,
	expected []uint64,
) (Noise, error) {
	plaintext := bgv.NewPlaintext(params, ciphertext.Level())
	*plaintext.MetaData = *ciphertext.MetaData
	if err := encoder.Encode(expected, plaintext); err != nil {
		return Noise{}, err
	}
	residual, err := bgv.NewEvaluator(params, nil, true).SubNew(ciphertext, plaintext)
	if err != nil {
		return Noise{}, err
	}

	std, minAbs, maxAbs := rlwe.Norm(residual, decryptor)
	budget := float64(params.RingQ().ModulusAtLevel[ciphertext.Level()].BitLen()) - 1 - maxAbs
	if math.IsInf(maxAbs, -1) {
		budget = math.Inf(1)
	}
	return Noise{Std: std, MinAbs: minAbs, MaxAbs: maxAbs, Budget: budget}, nil
}
