package charts_test

import (
	"math/bits"
	"testing"

	charts "github.com/anthony-s-flath/CHARTS/charts"
	"github.com/anthony-s-flath/CHARTS/internal/testutil"
)

// Exercise the configured circuit through collective opening and message recovery.
func TestMultipartyEvaluationKeysMatchCircuit(t *testing.T) {
	cfg := testutil.LoadConfig(t)
	params, n, width := cfg.Params, cfg.N, cfg.B

	senders, keys, err := charts.NewSenders(params, n, width, []byte("circuit-keys-test"))
	if err != nil {
		t.Fatal(err)
	}
	if width == n {
		if keys.RelinKey != nil || keys.GaloisKeys != nil {
			t.Fatal("direct circuit generated unused evaluation keys")
		}
	} else if keys.RelinKey == nil || len(keys.GaloisKeys) != bits.Len(uint(n/width))-1 {
		t.Fatal("expansion circuit is missing evaluation keys")
	}
	inputs := make([]charts.Message, n)
	requests := make([]charts.Request, n)
	for i := range inputs {
		inputs[i] = charts.Message{Tag: uint64(i), Coefficients: patternedMessage(params.N(), i+1, params.PlaintextModulus())}
		requests[i], err = senders[i].EncryptWithTag(inputs[i].Tag, inputs[i].Coefficients)
		if err != nil {
			t.Fatal(err)
		}
		if (requests[i].Control == nil) != (width == n) {
			t.Fatal("control ciphertext does not match circuit")
		}
	}
	router, err := charts.NewRouter(params, n, width, keys.RelinKey, keys.GaloisKeys)
	if err != nil {
		t.Fatal(err)
	}
	if err = router.Route(requests); err != nil {
		t.Fatal(err)
	}
	output := router.Output()
	for _, ct := range output.Payloads {
		if ct.Degree() != 1 {
			t.Fatal("output is not degree one")
		}
	}
	partials := make([]charts.PartialDecryption, n)
	for i := range senders {
		partials[i], err = senders[i].PartialDecrypt(output, cfg.Noise)
		if err != nil {
			t.Fatal(err)
		}
	}
	opened, err := router.AggregatePartialDecryptions(output, partials, cfg.Noise)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := charts.Decode(opened, params)
	if err != nil {
		t.Fatal(err)
	}
	assertMessages(t, recovered, inputs)
}
