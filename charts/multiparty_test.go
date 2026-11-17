package charts_test

import (
	"testing"

	charts "github.com/anthony-s-flath/CHARTS/charts"
	"github.com/anthony-s-flath/CHARTS/internal/testutil"
)

func TestMultipartyRoutingAndOutput(t *testing.T) {
	cfg := testutil.LoadConfig(t)
	params, n, b := cfg.Params, cfg.N, cfg.B
	inputs := make([]charts.Message, n)
	for i := range inputs {
		inputs[i] = charts.Message{Tag: uint64(i), Coefficients: patternedMessage(params.N(), i+1, params.PlaintextModulus())}
	}

	senders, keys, err := charts.NewSenders(
		params,
		n,
		b,
		[]byte("multiparty-routing-test"),
	)
	if err != nil {
		t.Fatal(err)
	}
	for senderIndex, sender := range senders {
		if sender.Share == nil {
			t.Fatalf(
				"sender %d has no secret-key share",
				senderIndex,
			)
		}
	}

	requests := make([]charts.Request, n)
	for sender, input := range inputs {
		requests[sender], err = senders[sender].EncryptWithTag(
			input.Tag,
			input.Coefficients,
		)
		if err != nil {
			t.Fatal(err)
		}
	}

	router, err := charts.NewRouter(
		params,
		n,
		b,
		keys.RelinKey,
		keys.GaloisKeys,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := router.Route(requests); err != nil {
		t.Fatal(err)
	}

	output := router.Output()
	partials := make([]charts.PartialDecryption, len(senders))
	for sender := range senders {
		partials[sender], err = senders[sender].PartialDecrypt(
			output,
			cfg.Noise,
		)
		if err != nil {
			t.Fatalf("sender %d partial decryption: %v", sender, err)
		}
		if len(partials[sender].Payloads) != n {
			t.Fatalf(
				"sender %d produced %d payload shares; want n=%d",
				sender,
				len(partials[sender].Payloads),
				n,
			)
		}
	}
	opened, err := router.AggregatePartialDecryptions(
		output,
		partials,
		cfg.Noise,
	)
	if err != nil {
		t.Fatal(err)
	}
	messages, err := charts.Decode(opened, params)
	if err != nil {
		t.Fatal(err)
	}
	assertMessages(t, messages, inputs)

	if _, err := router.AggregatePartialDecryptions(
		output,
		partials[:len(partials)-1],
		cfg.Noise,
	); err == nil {
		t.Fatal("router accepted an incomplete partial-decryption set")
	}
}
