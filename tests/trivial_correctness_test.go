package tests_test

import (
	"testing"

	charts "github.com/anthony-s-flath/CHARTS/charts"
	"github.com/anthony-s-flath/CHARTS/internal/testutil"
)

// TestRoutingCorrectness exercises the selected profile and circuit.
func TestRoutingCorrectness(t *testing.T) {
	cfg := testutil.LoadConfig(t)
	params, n, b := cfg.Params, cfg.N, cfg.B
	context := testutil.NewForRouting(params, n, b)

	senderParty, err := charts.NewSender(
		params,
		context.PublicKey,
		context.SecretKey,
		n,
		b,
	)
	if err != nil {
		t.Fatal(err)
	}
	router, err := charts.NewRouter(
		params,
		n,
		b,
		context.RelinKey,
		context.GaloisKeys,
	)
	if err != nil {
		t.Fatal(err)
	}

	requests := make([]charts.Request, n)
	want := make(map[uint64][]uint64, n)
	for sender := range requests {
		tag := uint64(sender)
		message := make([]uint64, params.N())
		for coefficient := range message {
			message[coefficient] = uint64(
				(sender+1)*(coefficient+1),
			) % params.PlaintextModulus()
		}
		requests[sender], err = senderParty.EncryptWithTag(tag, message)
		if err != nil {
			t.Fatalf("encrypt request %d: %v", sender, err)
		}
		want[tag] = message
	}

	if err := router.Route(requests); err != nil {
		t.Fatal(err)
	}
	opened, err := charts.Open(router.Output(), context.Decrypt)
	if err != nil {
		t.Fatal(err)
	}
	messages, err := charts.Decode(opened, params)
	if err != nil {
		t.Fatal(err)
	}
	if len(messages) != n {
		t.Fatalf("recovered %d messages; want n=%d", len(messages), n)
	}
	for _, message := range messages {
		coefficients, ok := want[message.Tag]
		if !ok {
			t.Fatalf("recovered unexpected tag %d", message.Tag)
		}
		if err := testutil.EqualPrefix(
			message.Coefficients,
			coefficients,
		); err != nil {
			t.Fatalf("tag %d: %v", message.Tag, err)
		}
	}
}
