package charts_test

import (
	"math/bits"
	"testing"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"

	charts "github.com/anthony-s-flath/CHARTS/charts"
	"github.com/anthony-s-flath/CHARTS/internal/testutil"
)

func TestCoefficientEncryption(t *testing.T) {
	cfg := testutil.LoadConfig(t)
	params, n, b := cfg.Params, cfg.N, cfg.B
	context := testutil.NewForRouting(params, n, b)
	want := []uint64{0, 1, 7, 255, 65_536}
	for i := range want {
		want[i] %= params.PlaintextModulus()
	}

	ciphertext, err := context.Encrypt(want)
	if err != nil {
		t.Fatal(err)
	}
	have, err := context.Decrypt(ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if err := testutil.EqualPrefix(have, want); err != nil {
		t.Fatal(err)
	}
}

func TestRequestEncoding(t *testing.T) {
	cfg := testutil.LoadConfig(t)
	params, n, b := cfg.Params, cfg.N, cfg.B
	context := testutil.NewForRouting(params, n, b)
	const tag = uint64(1)
	message := patternedMessage(
		params.N(),
		1,
		params.PlaintextModulus(),
	)

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
	plain, err := senderParty.PrepareWithTag(tag, message)
	if err != nil {
		t.Fatal(err)
	}
	wantControlLength := 0
	if b != n {
		wantControlLength = params.N()
	}
	if len(plain.Header) != n+1 ||
		len(plain.Control) != wantControlLength ||
		len(plain.Payloads) != b {
		t.Fatal("prepared request has an invalid layout")
	}
	for remainder, payload := range plain.Payloads {
		if len(payload) != params.N() {
			t.Fatalf(
				"prepared payload %d has %d coefficients; want N=%d",
				remainder,
				len(payload),
				params.N(),
			)
		}
	}

	request, err := senderParty.EncryptPrepared(plain)
	if err != nil {
		t.Fatal(err)
	}

	header, err := context.Decrypt(request.Header)
	if err != nil {
		t.Fatal(err)
	}
	wantHeader := make([]uint64, n+1)
	power := uint64(1)
	for moment := range wantHeader {
		wantHeader[moment] = power
		power = fieldMultiply(power, tag, params.PlaintextModulus())
	}
	if err := testutil.EqualPrefix(header, wantHeader); err != nil {
		t.Fatalf("header: %v", err)
	}

	if b != n {
		control, err := context.Decrypt(request.Control)
		if err != nil {
			t.Fatal(err)
		}
		wantControl := make([]uint64, params.N())
		factorCount := n / b
		coefficientGap := params.N() / factorCount
		for factor := 0; factor < factorCount; factor++ {
			wantControl[factor*coefficientGap] = fieldPower(
				tag,
				uint64(factor*b),
				params.PlaintextModulus(),
			)
		}
		if err := testutil.EqualPrefix(control, wantControl); err != nil {
			t.Fatalf("control: %v", err)
		}

	} else if request.Control != nil {
		t.Fatal("direct request contains a control ciphertext")
	}

	if len(request.Payloads) != b {
		t.Fatalf(
			"weighted messages=%d; want b=%d",
			len(request.Payloads),
			b,
		)
	}
	for remainder, ciphertext := range request.Payloads {
		have, err := context.Decrypt(ciphertext)
		if err != nil {
			t.Fatal(err)
		}
		want := make([]uint64, len(message))
		weight := fieldPower(
			tag,
			uint64(remainder),
			params.PlaintextModulus(),
		)
		for i, coefficient := range message {
			want[i] = fieldMultiply(
				weight,
				coefficient,
				params.PlaintextModulus(),
			)
		}
		if err := testutil.EqualPrefix(have, want); err != nil {
			t.Fatalf("weighted message %d: %v", remainder, err)
		}
	}
}

func TestDirectRouteOmitsControlAndRecoversBatch(t *testing.T) {
	cfg := testutil.LoadConfig(t)
	params, n, b := cfg.Params, cfg.N, cfg.B
	if b != n {
		t.Skip("direct routing is exercised when CHARTS_B=n")
	}
	context := testutil.NewForRouting(params, n, b)

	senderParty, err := charts.NewSender(
		params,
		context.PublicKey,
		context.SecretKey,
		n,
		n,
	)
	if err != nil {
		t.Fatal(err)
	}
	message := patternedMessage(
		params.N(),
		1,
		params.PlaintextModulus(),
	)
	plain, err := senderParty.PrepareWithTag(2, message)
	if err != nil {
		t.Fatal(err)
	}
	if plain.Control != nil {
		t.Fatal("direct request contains a control plaintext")
	}
	request, err := senderParty.EncryptPrepared(plain)
	if err != nil {
		t.Fatal(err)
	}
	if request.Control != nil {
		t.Fatal("direct request contains a control ciphertext")
	}
	if len(request.Payloads) != n {
		t.Fatalf("direct request has %d payloads; want %d", len(request.Payloads), n)
	}

	router, err := charts.NewRouter(
		params,
		n,
		n,
		context.RelinKey,
		context.GaloisKeys,
	)
	if err != nil {
		t.Fatal(err)
	}
	requests, want := requestsForTags(
		t,
		senderParty,
		tagsForBatch(n, params.PlaintextModulus(), 0),
		params.N(),
		params.PlaintextModulus(),
	)
	for sender, request := range requests {
		if request.Control != nil {
			t.Fatalf("direct request %d contains a control ciphertext", sender)
		}
	}
	if err := router.Route(requests); err != nil {
		t.Fatal(err)
	}
	opened, err := charts.Open(router.Output(), context.Decrypt)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := charts.Decode(opened, params)
	if err != nil {
		t.Fatal(err)
	}
	assertMessages(t, recovered, want)
}

func TestRouteRecoversCompleteBatch(t *testing.T) {
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
	want := make([]charts.Message, n)
	for sender := range requests {
		tag := uint64(sender)
		message := patternedMessage(
			params.N(),
			sender+1,
			params.PlaintextModulus(),
		)
		requests[sender], err = senderParty.EncryptWithTag(tag, message)
		if err != nil {
			t.Fatalf("encrypt request %d: %v", sender, err)
		}
		want[sender] = charts.Message{
			Tag:          tag,
			Coefficients: message,
		}
	}

	if err := router.Route(requests); err != nil {
		t.Fatal(err)
	}

	opened, err := charts.Open(router.Output(), context.Decrypt)
	if err != nil {
		t.Fatal(err)
	}
	wantOpened := aggregateMessages(
		want,
		params.N(),
		params.PlaintextModulus(),
	)
	if err := testutil.EqualPrefix(
		opened.Header,
		wantOpened.Header,
	); err != nil {
		t.Fatalf("header aggregates: %v", err)
	}
	for moment := range opened.Payloads {
		if err := testutil.EqualPrefix(
			opened.Payloads[moment],
			wantOpened.Payloads[moment],
		); err != nil {
			t.Fatalf("payload aggregate %d: %v", moment, err)
		}
	}

	recovered, err := charts.Decode(opened, params)
	if err != nil {
		t.Fatal(err)
	}
	assertMessages(t, recovered, want)
}

func TestRouteSupportsFullLengthMessages(t *testing.T) {
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
	want := make([]charts.Message, n)
	for sender := range requests {
		message := make([]uint64, params.N())
		for coefficient := range message {
			message[coefficient] = uint64(
				(sender+1)*(coefficient+1),
			) % params.PlaintextModulus()
		}
		tag := uint64(sender+1) % params.PlaintextModulus()
		requests[sender], err = senderParty.EncryptWithTag(tag, message)
		if err != nil {
			t.Fatal(err)
		}
		want[sender] = charts.Message{
			Tag:          tag,
			Coefficients: message,
		}
	}

	if err := router.Route(requests); err != nil {
		t.Fatal(err)
	}
	opened, err := charts.Open(router.Output(), context.Decrypt)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := charts.Decode(opened, params)
	if err != nil {
		t.Fatal(err)
	}
	assertMessages(t, recovered, want)
}

func TestRouteResetsAndReusesOutput(t *testing.T) {
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

	header := router.Output().Header
	payloads := append(
		[]*rlwe.Ciphertext(nil),
		router.Output().Payloads...,
	)
	first, _ := requestsForTags(
		t,
		senderParty,
		tagsForBatch(n, params.PlaintextModulus(), 0),
		params.N(),
		params.PlaintextModulus(),
	)
	second, want := requestsForTags(
		t,
		senderParty,
		tagsForBatch(n, params.PlaintextModulus(), 1),
		params.N(),
		params.PlaintextModulus(),
	)

	if err := router.Route(first); err != nil {
		t.Fatal(err)
	}
	if err := router.Route(second); err != nil {
		t.Fatal(err)
	}
	if router.Output().Header != header {
		t.Fatal("Route replaced the header ciphertext")
	}
	for moment := range payloads {
		if router.Output().Payloads[moment] != payloads[moment] {
			t.Fatalf(
				"Route replaced payload aggregate %d",
				moment,
			)
		}
	}

	opened, err := charts.Open(router.Output(), context.Decrypt)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := charts.Decode(opened, params)
	if err != nil {
		t.Fatal(err)
	}
	assertMessages(t, recovered, want)
}

func TestSenderSamplesValidTag(t *testing.T) {
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

	request, tag, err := senderParty.Encrypt(
		patternedMessage(
			params.N(),
			1,
			params.PlaintextModulus(),
		),
	)
	if err != nil {
		t.Fatal(err)
	}
	if request.Header == nil ||
		(request.Control == nil) != (b == n) ||
		len(request.Payloads) != b {
		t.Fatal("incomplete request")
	}
	if tag >= params.PlaintextModulus() {
		t.Fatalf(
			"tag=%d is outside the plaintext field",
			tag,
		)
	}
}

func TestSenderRejectsShortenedPayload(t *testing.T) {
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

	if _, err := senderParty.PrepareWithTag(
		1,
		make([]uint64, params.N()-1),
	); err == nil {
		t.Fatal("PrepareWithTag accepted a message shorter than N")
	}
}

func requestsForTags(
	t *testing.T,
	senderParty *charts.Sender,
	tags []uint64,
	messageLength int,
	modulus uint64,
) ([]charts.Request, []charts.Message) {
	t.Helper()
	requests := make([]charts.Request, len(tags))
	messages := make([]charts.Message, len(tags))
	for sender, tag := range tags {
		message := patternedMessage(
			messageLength,
			sender+1,
			modulus,
		)
		var err error
		requests[sender], err = senderParty.EncryptWithTag(tag, message)
		if err != nil {
			t.Fatalf("encrypt request %d: %v", sender, err)
		}
		messages[sender] = charts.Message{
			Tag:          tag,
			Coefficients: message,
		}
	}
	return requests, messages
}

func aggregateMessages(
	messages []charts.Message,
	messageLength int,
	modulus uint64,
) charts.OpenedOutput {
	output := charts.OpenedOutput{
		Header:   make([]uint64, len(messages)+1),
		Payloads: make([][]uint64, len(messages)),
	}
	for moment := range output.Payloads {
		output.Payloads[moment] = make(
			[]uint64,
			messageLength,
		)
	}
	for _, message := range messages {
		power := uint64(1)
		for moment := 0; moment <= len(messages); moment++ {
			output.Header[moment] =
				(output.Header[moment] + power) % modulus
			if moment < len(messages) {
				for coefficient, value := range message.Coefficients {
					output.Payloads[moment][coefficient] =
						(output.Payloads[moment][coefficient] +
							fieldMultiply(power, value, modulus)) % modulus
				}
			}
			power = fieldMultiply(power, message.Tag, modulus)
		}
	}
	return output
}

func assertMessages(
	t *testing.T,
	have []charts.Message,
	want []charts.Message,
) {
	t.Helper()
	if len(have) != len(want) {
		t.Fatalf(
			"recovered %d messages; want %d",
			len(have),
			len(want),
		)
	}
	wantByTag := make(map[uint64][]uint64, len(want))
	for _, message := range want {
		wantByTag[message.Tag] = message.Coefficients
	}
	for _, message := range have {
		coefficients, ok := wantByTag[message.Tag]
		if !ok {
			t.Fatalf("recovered unexpected tag %d", message.Tag)
		}
		if len(message.Coefficients) != len(coefficients) {
			t.Fatalf(
				"tag %d has %d coefficients; want %d",
				message.Tag,
				len(message.Coefficients),
				len(coefficients),
			)
		}
		for coefficient := range coefficients {
			if message.Coefficients[coefficient] != coefficients[coefficient] {
				t.Fatalf(
					"tag %d coefficient %d: have %d, want %d",
					message.Tag,
					coefficient,
					message.Coefficients[coefficient],
					coefficients[coefficient],
				)
			}
		}
	}
}

func patternedMessage(
	length int,
	sender int,
	modulus uint64,
) []uint64 {
	message := make([]uint64, length)
	for coefficient := range message {
		message[coefficient] = uint64(
			(sender+1)*(coefficient+1)+sender*sender,
		) % modulus
	}
	return message
}

func fieldPower(base, exponent, modulus uint64) uint64 {
	result := uint64(1)
	for exponent != 0 {
		if exponent&1 == 1 {
			result = fieldMultiply(result, base, modulus)
		}
		exponent >>= 1
		if exponent != 0 {
			base = fieldMultiply(base, base, modulus)
		}
	}
	return result
}

func fieldMultiply(left, right, modulus uint64) uint64 {
	high, low := bits.Mul64(left, right)
	_, remainder := bits.Div64(high, low, modulus)
	return remainder
}

// Consecutive tags remain distinct whenever the configured n<t invariant holds.
func tagsForBatch(n int, modulus uint64, offset int) []uint64 {
	tags := make([]uint64, n)
	for i := range tags {
		tags[i] = uint64(i+offset) % modulus
	}
	return tags
}
