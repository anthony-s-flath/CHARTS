package charts_test

import (
	"github.com/anthony-s-flath/CHARTS/internal/testutil"
	"github.com/tuneinsight/lattigo/v6/ring"
	"slices"
	"testing"

	charts "github.com/anthony-s-flath/CHARTS/charts"
)

func TestDecodeRecoversFullLengthMessages(t *testing.T) {
	cfg := testutil.LoadConfig(t)
	params := cfg.Params
	want := make([]charts.Message, cfg.N)
	for i := range want {
		want[i] = charts.Message{Tag: uint64(i), Coefficients: patternedMessage(params.N(), i+1, params.PlaintextModulus())}
	}
	output := aggregateMessages(want, params.N(), params.PlaintextModulus())

	have, err := charts.Decode(output, params)
	if err != nil {
		t.Fatal(err)
	}
	assertMessages(t, have, want)
}

func TestDecodeRejectsPartialPayloads(t *testing.T) {
	cfg := testutil.LoadConfig(t)
	params := cfg.Params
	want := make([]charts.Message, cfg.N)
	for i := range want {
		want[i] = charts.Message{Tag: uint64(i), Coefficients: patternedMessage(params.N(), i+1, params.PlaintextModulus())}
	}
	output := aggregateMessages(want, params.N(), params.PlaintextModulus())
	output.Payloads[0] = output.Payloads[0][:params.N()-1]

	if _, err := charts.Decode(output, params); err == nil {
		t.Fatal("Decode accepted a payload shorter than N")
	}
}

func TestDecodeTagsDoesNotRequirePayloads(t *testing.T) {
	cfg := testutil.LoadConfig(t)
	modulus := cfg.Params.PlaintextModulus()
	want := tagsForBatch(cfg.N, modulus, 0)
	header := aggregateHeader(want, modulus)

	have, err := charts.DecodeTags(header, len(want), modulus)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(have, want) {
		t.Fatalf("tags=%v; want %v", have, want)
	}
}

func TestDecodeTagsRejectsInvalidUserCount(t *testing.T) {
	cfg := testutil.LoadConfig(t)
	modulus := cfg.Params.PlaintextModulus()
	header := aggregateHeader(tagsForBatch(cfg.N, modulus, 0), modulus)
	header[0] = uint64(cfg.N - 1)

	if _, err := charts.DecodeTags(
		header,
		cfg.N,
		modulus,
	); err == nil {
		t.Fatal("DecodeTags accepted an incorrect H_0")
	}
}

func TestDecodeTagsRejectsInvalidTags(t *testing.T) {
	cfg := testutil.LoadConfig(t)
	modulus := cfg.Params.PlaintextModulus()

	duplicate := aggregateHeader([]uint64{1, 1}, modulus)
	if _, err := charts.DecodeTags(
		duplicate,
		2,
		modulus,
	); err == nil {
		t.Fatal("DecodeTags accepted duplicate tags")
	}

	// H_1=0 and H_2=2c produce Z^2-c. Select a quadratic non-residue
	// for the configured field rather than assuming five is always one.
	c := uint64(2)
	for ring.ModExp(c, (modulus-1)/2, modulus) != modulus-1 {
		c++
	}
	if _, err := charts.DecodeTags(
		[]uint64{2, 0, (2 * c) % modulus},
		2,
		modulus,
	); err == nil {
		t.Fatal("DecodeTags accepted a nonsplitting tag polynomial")
	}
}

func TestDecodeTagsDoesNotScaleLinearlyWithModulus(t *testing.T) {
	cfg := testutil.LoadConfig(t)
	modulus := cfg.Params.PlaintextModulus()
	want := make([]uint64, cfg.N)
	for i := range want {
		want[i] = modulus - uint64(cfg.N) + uint64(i)
	}
	header := aggregateHeader(want, modulus)

	have, err := charts.DecodeTags(header, len(want), modulus)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(have, want) {
		t.Fatalf("tags=%v; want %v", have, want)
	}
}

func aggregateHeader(tags []uint64, modulus uint64) []uint64 {
	header := make([]uint64, len(tags)+1)
	for _, tag := range tags {
		power := uint64(1)
		for moment := range header {
			header[moment] = (header[moment] + power) % modulus
			power = fieldMultiply(power, tag, modulus)
		}
	}
	return header
}
