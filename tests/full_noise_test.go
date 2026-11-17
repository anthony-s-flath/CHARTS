package tests_test

import (
	"math"
	"math/bits"
	"testing"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/multiparty"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"

	charts "github.com/anthony-s-flath/CHARTS/charts"
	"github.com/anthony-s-flath/CHARTS/internal/config"
	"github.com/anthony-s-flath/CHARTS/internal/testutil"
)

func TestFullNoiseAndCorrectness(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping full paper-parameter noise test in short mode")
	}

	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	t.Log(cfg.String())
	params, n, b := cfg.Params, cfg.N, cfg.B

	messageLength := params.N()

	// Generate n independent sender secret-key shares together with the
	// collective public, relinearization, and Galois keys.
	senders, keys, err := charts.NewSenders(
		params,
		n,
		b,
		[]byte("charts-full-multiparty-routing-noise"),
	)
	if err != nil {
		t.Fatal(err)
	}

	// Construct the collective secret key only as a testing oracle.
	collectiveSecretKey := rlwe.NewSecretKey(params)
	for _, sender := range senders {
		params.RingQP().Add(
			collectiveSecretKey.Value,
			sender.Share.Value,
			collectiveSecretKey.Value,
		)
	}

	encoder := bgv.NewEncoder(params)
	collectiveDecryptor := bgv.NewDecryptor(
		params,
		collectiveSecretKey,
	)

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

	requests := make([]charts.Request, n)
	tags := make([]uint64, n)
	messages := make([][]uint64, n)

	for sender := range requests {
		tags[sender] = uint64(sender + 2)

		messages[sender] = make([]uint64, messageLength)
		for coefficient := range messages[sender] {
			messages[sender][coefficient] = uint64(
				(sender+1)*(coefficient+1),
			) % params.PlaintextModulus()
		}

		// Each sender uses its OWN secret-key share and the collective
		// public key.
		requests[sender], err = senders[sender].EncryptWithTag(
			tags[sender],
			messages[sender],
		)
		if err != nil {
			t.Fatalf("encrypt request %d: %v", sender, err)
		}
	}

	// Expected plaintext form of the first request.
	firstHeader, firstControl, firstPayloads := expectedRequest(
		params.N(),
		n,
		b,
		tags[0],
		messages[0],
		params.PlaintextModulus(),
	)

	logMultipartyNoise(
		t,
		"fresh header      ",
		params,
		encoder,
		collectiveDecryptor,
		requests[0].Header,
		firstHeader,
	)

	if n != b {
		logMultipartyNoise(
			t,
			"fresh control     ",
			params,
			encoder,
			collectiveDecryptor,
			requests[0].Control,
			firstControl,
		)
	}

	logMultipartyNoise(
		t,
		"fresh weighted msg",
		params,
		encoder,
		collectiveDecryptor,
		requests[0].Payloads[b-1],
		firstPayloads[b-1],
	)

	// Execute the CHARTS routing circuit.
	if err := router.Route(requests); err != nil {
		t.Fatal(err)
	}

	wantHeader, wantPayloads := expectedOutput(
		n,
		messageLength,
		tags,
		messages,
		params.PlaintextModulus(),
	)

	output := router.Output()

	// Measure the routed ciphertexts before collective decryption.
	logMultipartyNoise(
		t,
		"routed header       ",
		params,
		encoder,
		collectiveDecryptor,
		output.Header,
		wantHeader,
	)

	logMultipartyNoise(
		t,
		"routed payload n-1",
		params,
		encoder,
		collectiveDecryptor,
		output.Payloads[n-1],
		wantPayloads[n-1],
	)

	// Use CHARTS's configured smudging distribution.
	noise := cfg.Noise

	// Every sender independently generates its partial-decryption shares.
	partials := make([]charts.PartialDecryption, n)

	for senderIndex, sender := range senders {
		partials[senderIndex], err = sender.PartialDecrypt(
			output,
			noise,
		)
		if err != nil {
			t.Fatalf(
				"partial decrypt sender %d: %v",
				senderIndex,
				err,
			)
		}
	}

	// For diagnostics, reconstruct the key-switched n-1 payload so that
	// we can measure the noise after collective key switching.
	logCollectivelySwitchedNoise(
		t,
		"switched payload n-1",
		params,
		encoder,
		output.Payloads[n-1],
		partials,
		n-1,
		noise,
		wantPayloads[n-1],
	)

	// This is the actual CHARTS collective opening path:
	//
	//   partial shares
	//       -> aggregate shares
	//       -> key switch collective secret -> zero
	//       -> decrypt with zero secret key
	opened, err := router.AggregatePartialDecryptions(
		output,
		partials,
		noise,
	)
	if err != nil {
		t.Fatal(err)
	}

	if err := testutil.EqualPrefix(
		opened.Header,
		wantHeader,
	); err != nil {
		t.Fatalf("header: %v", err)
	}

	for moment := range wantPayloads {
		if err := testutil.EqualPrefix(
			opened.Payloads[moment],
			wantPayloads[moment],
		); err != nil {
			t.Fatalf(
				"payload aggregate %d: %v",
				moment,
				err,
			)
		}
	}

	// Run CHARTS's actual recovery algorithm on the collectively opened
	// output.
	if _, err := charts.Decode(opened, params); err != nil {
		t.Fatalf("recover messages: %v", err)
	}
}

func logMultipartyNoise(
	t *testing.T,
	name string,
	params bgv.Parameters,
	encoder *bgv.Encoder,
	decryptor *rlwe.Decryptor,
	ciphertext *rlwe.Ciphertext,
	expected []uint64,
) {
	t.Helper()

	noise, err := charts.MeasureNoise(
		params,
		encoder,
		decryptor,
		ciphertext,
		expected,
	)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}

	if math.IsNaN(noise.Std) ||
		math.IsNaN(noise.MaxAbs) ||
		math.IsNaN(noise.Budget) {
		t.Fatalf(
			"%s: invalid noise report %+v",
			name,
			noise,
		)
	}

	t.Logf(
		"%s: \t\t log2(std)=%.2f \t log2(max)=%.2f \t raw-budget=%.2f",
		name,
		noise.Std,
		noise.MaxAbs,
		noise.Budget,
	)
}

func logCollectivelySwitchedNoise(
	t *testing.T,
	name string,
	params bgv.Parameters,
	encoder *bgv.Encoder,
	ciphertext *rlwe.Ciphertext,
	partials []charts.PartialDecryption,
	moment int,
	noise ring.DistributionParameters,
	expected []uint64,
) {
	t.Helper()

	// Reconstruct exactly the same collective key-switch operation used
	// by Router.AggregatePartialDecryptions, but retain the resulting
	// ciphertext so that MeasureNoise can inspect it.
	protocol, err := multiparty.NewKeySwitchProtocol(
		params,
		noise,
	)
	if err != nil {
		t.Fatalf("%s: create key-switch protocol: %v", name, err)
	}

	combined := protocol.AllocateShare(ciphertext.Level())

	for sender := range partials {
		if err := protocol.AggregateShares(
			partials[sender].Payloads[moment],
			combined,
			&combined,
		); err != nil {
			t.Fatalf(
				"%s: aggregate share %d: %v",
				name,
				sender,
				err,
			)
		}
	}

	switched := bgv.NewCiphertext(
		params,
		1,
		ciphertext.Level(),
	)

	protocol.KeySwitch(
		ciphertext,
		combined,
		switched,
	)

	// After collective key switching the target key is zero, so an
	// all-zero secret key is the correct diagnostic decryptor.
	zeroSecretKey := rlwe.NewSecretKey(params)
	zeroDecryptor := bgv.NewDecryptor(
		params,
		zeroSecretKey,
	)

	logMultipartyNoise(
		t,
		name,
		params,
		encoder,
		zeroDecryptor,
		switched,
		expected,
	)
}

func logNoise(
	t *testing.T,
	name string,
	context *testutil.Context,
	ciphertext *rlwe.Ciphertext,
	expected []uint64,
) {
	t.Helper()

	noise, err := charts.MeasureNoise(
		context.Params,
		context.Encoder,
		context.Decryptor,
		ciphertext,
		expected,
	)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	if math.IsNaN(noise.Std) ||
		math.IsNaN(noise.MaxAbs) ||
		math.IsNaN(noise.Budget) {
		t.Fatalf("%s: invalid noise report %+v", name, noise)
	}
	t.Logf(
		"%s: \t\t log2(std)=%.2f \t log2(max)=%.2f \t raw-budget=%.2f",
		name,
		noise.Std,
		noise.MaxAbs,
		noise.Budget,
	)
}

func expectedRequest(
	ringDegree int,
	n int,
	b int,
	tag uint64,
	message []uint64,
	modulus uint64,
) (
	header []uint64,
	control []uint64,
	payloads [][]uint64,
) {
	header = make([]uint64, n+1)
	power := uint64(1)
	for moment := range header {
		header[moment] = power
		power = fieldMultiply(power, tag, modulus)
	}

	control = make([]uint64, ringDegree)
	factorCount := n / b
	coefficientGap := ringDegree / factorCount
	for factor := 0; factor < factorCount; factor++ {
		control[factor*coefficientGap] = powerMod(
			tag,
			uint64(factor*b),
			modulus,
		)
	}

	payloads = make([][]uint64, b)
	for remainder := range payloads {
		payloads[remainder] = make([]uint64, len(message))
		weight := powerMod(
			tag,
			uint64(remainder),
			modulus,
		)
		for coefficient, value := range message {
			payloads[remainder][coefficient] = fieldMultiply(
				weight,
				value,
				modulus,
			)
		}
	}
	return
}

func expectedOutput(
	n int,
	messageLength int,
	tags []uint64,
	messages [][]uint64,
	modulus uint64,
) ([]uint64, [][]uint64) {
	header := make([]uint64, n+1)
	payloads := make([][]uint64, n)
	for moment := range payloads {
		payloads[moment] = make([]uint64, messageLength)
	}

	for sender, tag := range tags {
		power := uint64(1)
		for moment := 0; moment <= n; moment++ {
			header[moment] = (header[moment] + power) % modulus
			if moment < n {
				for coefficient, value := range messages[sender] {
					payloads[moment][coefficient] =
						(payloads[moment][coefficient] +
							fieldMultiply(power, value, modulus)) % modulus
				}
			}
			power = fieldMultiply(power, tag, modulus)
		}
	}
	return header, payloads
}

func powerMod(base, exponent, modulus uint64) uint64 {
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
