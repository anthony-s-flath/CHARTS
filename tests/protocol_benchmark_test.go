package tests_test

import (
	"fmt"
	"runtime"
	"testing"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"

	charts "github.com/anthony-s-flath/CHARTS/charts"
	"github.com/anthony-s-flath/CHARTS/internal/config"
)

var (
	plainRequestSink      charts.PlainRequest
	requestSink           charts.Request
	partialSink           charts.PartialDecryption
	openedOutputSink      charts.OpenedOutput
	messagesSink          []charts.Message
	tagSink               uint64
	expandedControlSink   map[int]*rlwe.Ciphertext
	benchmarkFixtureCache *benchmarkFixture
)

type benchmarkFixture struct {
	noise       ring.DistributionParameters
	params      bgv.Parameters
	senders     []*charts.Sender
	sender      *charts.Sender
	message     []uint64
	plain       charts.PlainRequest
	requests    []charts.Request
	router      *charts.Router
	relinRouter *charts.Router
	direct      bool
	expanded    []map[int]*rlwe.Ciphertext
	relinReady  bool
	output      charts.Output
	partials    []charts.PartialDecryption
	opened      charts.OpenedOutput
}

// BenchmarkProtocol measures one protocol operation per sub-benchmark.
// Go controls the iteration count, elapsed time, repetitions, and statistics.
func BenchmarkProtocol(b *testing.B) {
	cfg, err := config.Load()
	if err != nil {
		b.Fatal(err)
	}
	b.Log(cfg.String())
	name := fmt.Sprintf("%s/n=%d/b=%d", cfg.Profile, cfg.N, cfg.B)

	b.Run(name, func(b *testing.B) {
		fixture := newBenchmarkFixture(b, cfg)
		benchmarkRequests(b, fixture)
		benchmarkRouting(b, fixture)
		benchmarkOpening(b, fixture)
	})
}

func benchmarkRequests(b *testing.B, fixture *benchmarkFixture) {
	b.Run("Request", func(b *testing.B) {
		b.Run("Generate", func(b *testing.B) {
			for b.Loop() {
				var err error
				plainRequestSink, tagSink, err = fixture.sender.Prepare(fixture.message)
				if err != nil {
					b.Fatal(err)
				}
			}
		})

		b.Run("Encrypt", func(b *testing.B) {
			for b.Loop() {
				var err error
				requestSink, err = fixture.sender.EncryptPrepared(fixture.plain)
				if err != nil {
					b.Fatal(err)
				}
			}
		})

		b.Run("GenerateAndEncrypt", func(b *testing.B) {
			for b.Loop() {
				var err error
				requestSink, tagSink, err = fixture.sender.Encrypt(fixture.message)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	})
}

func benchmarkRouting(b *testing.B, fixture *benchmarkFixture) {
	b.Run("Routing", func(b *testing.B) {
		b.Run("Complete", func(b *testing.B) {
			for b.Loop() {
				if err := fixture.router.Route(fixture.requests); err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
			if fixture.output.Header == nil {
				fixture.output = cloneOutput(fixture.router.Output())
			}
		})

		b.Run("HeaderAggregation", func(b *testing.B) {
			for b.Loop() {
				b.StopTimer()
				if err := fixture.router.ValidateRoute(fixture.requests); err != nil {
					b.Fatal(err)
				}
				b.StartTimer()

				if err := fixture.router.AggregateHeaders(fixture.requests); err != nil {
					b.Fatal(err)
				}
			}
		})

		b.Run("ControlExpansion", func(b *testing.B) {
			if fixture.direct {
				b.Skip("control expansion is unused when b=n")
			}
			for b.Loop() {
				for _, request := range fixture.requests {
					var err error
					expandedControlSink, err = fixture.router.ExpandControl(request)
					if err != nil {
						b.Fatal(err)
					}
				}
			}
		})

		b.Run("PayloadAggregation", func(b *testing.B) {
			expanded := prepareExpandedControls(b, fixture)
			b.ResetTimer()

			for b.Loop() {
				b.StopTimer()
				if err := fixture.router.ValidateRoute(fixture.requests); err != nil {
					b.Fatal(err)
				}
				b.StartTimer()

				aggregatePayloads(b, fixture.router, fixture, expanded)
			}
		})

		b.Run("Relinearization", func(b *testing.B) {
			if fixture.direct {
				b.Skip("relinearization is unused when b=n")
			}
			router := prepareRelinearization(b, fixture)
			b.ResetTimer()

			for b.Loop() {
				if err := router.RelinearizePayloads(); err != nil {
					b.Fatal(err)
				}
			}
		})
	})
}

func benchmarkOpening(b *testing.B, fixture *benchmarkFixture) {
	b.Run("Opening", func(b *testing.B) {
		b.Run("PartialDecrypt", func(b *testing.B) {
			output := prepareRoutedOutput(b, fixture)
			b.ResetTimer()

			for b.Loop() {
				var err error
				partialSink, err = fixture.senders[0].PartialDecrypt(
					output,
					fixture.noise,
				)
				if err != nil {
					b.Fatal(err)
				}
			}
		})

		b.Run("AggregatePartialDecryptions", func(b *testing.B) {
			output, partials, _ := prepareOpening(b, fixture)
			b.ResetTimer()

			for b.Loop() {
				var err error
				openedOutputSink, err = fixture.router.AggregatePartialDecryptions(
					output,
					partials,
					fixture.noise,
				)
				if err != nil {
					b.Fatal(err)
				}
			}
		})

		b.Run("Decode", func(b *testing.B) {
			_, _, opened := prepareOpening(b, fixture)
			b.ResetTimer()

			for b.Loop() {
				var err error
				messagesSink, err = charts.Decode(opened, fixture.params)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	})
}

func prepareExpandedControls(
	b *testing.B,
	fixture *benchmarkFixture,
) []map[int]*rlwe.Ciphertext {
	b.Helper()
	if fixture.direct {
		return nil
	}
	if fixture.expanded != nil {
		return fixture.expanded
	}

	fixture.expanded = make(
		[]map[int]*rlwe.Ciphertext,
		len(fixture.requests),
	)
	for i, request := range fixture.requests {
		var err error
		fixture.expanded[i], err = fixture.router.ExpandControl(request)
		if err != nil {
			b.Fatal(err)
		}
	}
	return fixture.expanded
}

func prepareRelinearization(
	b *testing.B,
	fixture *benchmarkFixture,
) *charts.Router {
	b.Helper()
	if fixture.relinReady {
		return fixture.relinRouter
	}

	expanded := prepareExpandedControls(b, fixture)
	if err := fixture.relinRouter.ValidateRoute(fixture.requests); err != nil {
		b.Fatal(err)
	}
	aggregatePayloads(
		b,
		fixture.relinRouter,
		fixture,
		expanded,
	)
	fixture.relinReady = true
	return fixture.relinRouter
}

func aggregatePayloads(
	b *testing.B,
	router *charts.Router,
	fixture *benchmarkFixture,
	expanded []map[int]*rlwe.Ciphertext,
) {
	b.Helper()
	for i, request := range fixture.requests {
		var control map[int]*rlwe.Ciphertext
		if !fixture.direct {
			control = expanded[i]
		}
		if err := router.AggregatePayloads(request, control); err != nil {
			b.Fatal(err)
		}
	}
}

func routeBatch(b *testing.B, fixture *benchmarkFixture) charts.Output {
	b.Helper()
	if err := fixture.router.Route(fixture.requests); err != nil {
		b.Fatal(err)
	}
	return fixture.router.Output()
}

func prepareRoutedOutput(
	b *testing.B,
	fixture *benchmarkFixture,
) charts.Output {
	b.Helper()
	if fixture.output.Header != nil {
		return fixture.output
	}
	fixture.output = cloneOutput(routeBatch(b, fixture))
	return fixture.output
}

func cloneOutput(output charts.Output) charts.Output {
	cloned := charts.Output{
		Header:   output.Header.CopyNew(),
		Payloads: make([]*rlwe.Ciphertext, len(output.Payloads)),
	}
	for i, payload := range output.Payloads {
		cloned.Payloads[i] = payload.CopyNew()
	}
	return cloned
}

func prepareOpening(
	b *testing.B,
	fixture *benchmarkFixture,
) (charts.Output, []charts.PartialDecryption, charts.OpenedOutput) {
	b.Helper()
	output := prepareRoutedOutput(b, fixture)
	if fixture.partials != nil {
		return output, fixture.partials, fixture.opened
	}

	// release so we do not use too much memory
	fixture.requests = nil
	fixture.expanded = nil
	runtime.GC()

	partials := make([]charts.PartialDecryption, len(fixture.senders))
	for i, sender := range fixture.senders {
		var err error
		partials[i], err = sender.PartialDecrypt(output, fixture.noise)
		if err != nil {
			b.Fatalf("sender %d partial decryption: %v", i, err)
		}
	}
	opened, err := fixture.router.AggregatePartialDecryptions(
		output,
		partials,
		fixture.noise,
	)
	if err != nil {
		b.Fatal(err)
	}
	if _, err := charts.Decode(opened, fixture.params); err != nil {
		b.Fatalf("benchmark fixture does not decode: %v", err)
	}
	fixture.partials = partials
	fixture.opened = opened
	return output, fixture.partials, fixture.opened
}

func newBenchmarkFixture(
	b *testing.B,
	cfg config.Config,
) *benchmarkFixture {
	b.Helper()
	if benchmarkFixtureCache != nil {
		return benchmarkFixtureCache
	}

	params, n, width := cfg.Params, cfg.N, cfg.B
	senders, keys, err := charts.NewSenders(
		params,
		n,
		width,
		[]byte("charts-protocol-benchmark"),
	)
	if err != nil {
		b.Fatal(err)
	}
	sender := senders[0]
	message := benchmarkMessage(params)
	plain, err := sender.PrepareWithTag(2, message)
	if err != nil {
		b.Fatal(err)
	}

	requests := make([]charts.Request, n)
	for sender := range requests {
		requests[sender], err = senders[sender].EncryptWithTag(
			uint64(sender+2),
			message,
		)
		if err != nil {
			b.Fatalf("encrypt request %d: %v", sender, err)
		}
	}
	router, err := charts.NewRouter(
		params,
		n,
		width,
		keys.RelinKey,
		keys.GaloisKeys,
	)
	if err != nil {
		b.Fatal(err)
	}
	var relinRouter *charts.Router
	if n != width {
		relinRouter, err = charts.NewRouter(params, n, width, keys.RelinKey, keys.GaloisKeys)
		if err != nil {
			b.Fatal(err)
		}
	}

	fixture := &benchmarkFixture{
		noise:       cfg.Noise,
		params:      params,
		senders:     senders,
		sender:      sender,
		message:     message,
		plain:       plain,
		requests:    requests,
		router:      router,
		relinRouter: relinRouter,
		direct:      n == width,
	}
	benchmarkFixtureCache = fixture
	return fixture
}

func benchmarkMessage(params bgv.Parameters) []uint64 {
	message := make([]uint64, params.N())
	for coefficient := range message {
		message[coefficient] = uint64(coefficient+1) %
			params.PlaintextModulus()
	}
	return message
}
