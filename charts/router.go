package charts

import (
	"fmt"
	"math/bits"
	"runtime"
	"sync"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

// Output is the encrypted result of one n-request routing batch.
type Output struct {
	Header   *rlwe.Ciphertext
	Payloads []*rlwe.Ciphertext
}

// Router evaluates one fixed routing circuit using public evaluation keys.
// A Router processes one batch at a time.
type Router struct {
	params    bgv.Parameters
	layout    routingLayout
	output    Output
	pending   []*rlwe.Ciphertext
	evaluator *bgv.Evaluator
	packing   *rlwe.RingPackingEvaluator
	encoder   *bgv.Encoder
	decryptor *rlwe.Decryptor
}

// NewRouter constructs the public evaluator for the n-sender routing circuit.
func NewRouter(
	params bgv.Parameters,
	n int,
	b int,
	relinearizationKey *rlwe.RelinearizationKey,
	galoisKeys []*rlwe.GaloisKey,
) (*Router, error) {
	layout, err := newRoutingLayout(params, n, b)
	if err != nil {
		return nil, err
	}

	output := Output{
		Header:   newCiphertext(params, 1),
		Payloads: make([]*rlwe.Ciphertext, n),
	}
	for moment := range output.Payloads {
		output.Payloads[moment] = newCiphertext(params, 1)
	}

	var pending []*rlwe.Ciphertext
	var packing *rlwe.RingPackingEvaluator
	var evaluationKeys rlwe.EvaluationKeySet
	if layout.factorCount > 1 {
		pending = make([]*rlwe.Ciphertext, n)
		for moment := range pending {
			pending[moment] = newCiphertext(params, 2)
		}
		packing = newPackingEvaluator(params, galoisKeys)
		evaluationKeys = rlwe.NewMemEvaluationKeySet(
			relinearizationKey,
			galoisKeys...,
		)
	}

	return &Router{
		params:  params,
		layout:  layout,
		output:  output,
		pending: pending,
		evaluator: bgv.NewEvaluator(
			params,
			evaluationKeys,
			true,
		),
		packing:   packing,
		encoder:   bgv.NewEncoder(params),
		decryptor: bgv.NewDecryptor(params, rlwe.NewSecretKey(params)),
	}, nil
}

// Route expands every request's L control factors, multiplies each by the b
// weighted messages, accumulates the n moments at degree two, and
// relinearizes each aggregate once after the complete batch. When b=n, it
// directly adds the n weighted payloads without expansion or multiplication.
func (r *Router) Route(requests []Request) error {
	r.reset()
	r.AggregateHeaders(requests)
	// b = n
	if r.layout.factorCount == 1 {
		for _, request := range requests {
			r.AggregatePayloads(request, nil)
		}
		return nil
	}

	// b < n
	for _, request := range requests {
		expanded, _ := r.ExpandControl(request)
		r.AggregatePayloads(request, expanded)
		clear(expanded)
	}
	return r.RelinearizePayloads()
}

// ValidateRoute validates a complete batch and resets the reused output buffers.
func (r *Router) ValidateRoute(requests []Request) error {
	if len(requests) != r.layout.n {
		return fmt.Errorf("routing batch must contain n=%d requests", r.layout.n)
	}
	for _, request := range requests {
		if len(request.Payloads) != r.layout.b {
			return fmt.Errorf("request must contain b=%d weighted messages", r.layout.b)
		}
		if r.layout.factorCount > 1 && request.Control == nil {
			return fmt.Errorf("request must contain a control ciphertext")
		}
	}
	r.reset()
	return nil
}

// AggregateHeaders sums the request headers into the current output header.
// NOT PARALLELIZED
func (r *Router) AggregateHeaders(requests []Request) error {
	for _, request := range requests {
		if err := r.evaluator.Add(r.output.Header, request.Header, r.output.Header); err != nil {
			return err
		}
	}
	return nil
}

// ExpandControl extracts one request's L encrypted tag factors.
// PARALLELIZED (inside of ExpandSparse)
func (r *Router) ExpandControl(request Request) (map[int]*rlwe.Ciphertext, error) {
	if r.layout.factorCount == 1 {
		return nil, fmt.Errorf("control expansion is unused when b=n")
	}
	return ExpandSparse(
		r.packing,
		request.Control,
		r.layout.logCoefficientGap,
	)
}

// Parallelized aggregation of W
// PARALLELIZED
func (r *Router) AggregatePayloads(
	request Request,
	expanded map[int]*rlwe.Ciphertext,
) error {
	workerCount := min(runtime.GOMAXPROCS(0), r.layout.n)

	var wg sync.WaitGroup
	var errOnce sync.Once
	var firstErr error

	setErr := func(err error) {
		if err != nil {
			errOnce.Do(func() {
				firstErr = err
			})
		}
	}

	// Direct case: b = n
	if r.layout.factorCount == 1 {
		for worker_i := 0; worker_i < workerCount; worker_i++ {
			start := worker_i * r.layout.n / workerCount
			end := (worker_i + 1) * r.layout.n / workerCount

			wg.Add(1)

			go func(start, end int) {
				defer wg.Done()

				for moment := start; moment < end; moment++ {
					if err := r.evaluator.Add(
						r.output.Payloads[moment],
						request.Payloads[moment],
						r.output.Payloads[moment],
					); err != nil {
						setErr(err)
						return
					}
				}
			}(start, end)
		}

		wg.Wait()

		return firstErr
	}

	// General case: b < n
	for worker_i := 0; worker_i < workerCount; worker_i++ {
		start := worker_i * r.layout.n / workerCount
		end := (worker_i + 1) * r.layout.n / workerCount

		wg.Add(1)

		go func(start, end int) {
			defer wg.Done()

			for moment := start; moment < end; moment++ {
				factor := moment / r.layout.b
				remainder := moment % r.layout.b

				tagFactor := expanded[factor*r.layout.coefficientGap]

				payload := request.Payloads[remainder]

				if err := r.evaluator.MulThenAdd(
					tagFactor,
					payload,
					r.pending[moment],
				); err != nil {
					setErr(err)
					return
				}
			}
		}(start, end)
	}

	wg.Wait()

	return firstErr
}

// RelinearizePayloads converts every accumulated payload to degree one.
// PARALLELIZED
func (r *Router) RelinearizePayloads() error {
	workerCount := min(runtime.GOMAXPROCS(0), len(r.pending))

	var wg sync.WaitGroup
	var errOnce sync.Once
	var firstErr error

	for worker_i := 0; worker_i < workerCount; worker_i++ {
		start := worker_i * len(r.pending) / workerCount
		end := (worker_i + 1) * len(r.pending) / workerCount

		wg.Add(1)

		go func(start, end int) {
			defer wg.Done()

			for moment := start; moment < end; moment++ {
				if err := r.evaluator.Relinearize(
					r.pending[moment],
					r.output.Payloads[moment],
				); err != nil {
					errOnce.Do(func() {
						firstErr = err
					})
					return
				}
			}
		}(start, end)
	}

	wg.Wait()

	return firstErr
}

// Output returns a read-only view of the most recent routing result.
func (r *Router) Output() Output {
	return r.output
}

func (r *Router) reset() {
	zeroCiphertext(r.output.Header)
	for moment := range r.output.Payloads {
		zeroCiphertext(r.output.Payloads[moment])
	}
	for moment := range r.pending {
		zeroCiphertext(r.pending[moment])
	}
}

type routingLayout struct {
	n                 int // number of senders and moments
	b                 int // weighted messages per request
	factorCount       int // L = n/b
	coefficientGap    int // g = N/L
	logCoefficientGap int
}

func newRoutingLayout(
	params bgv.Parameters,
	n int,
	b int,
) (routingLayout, error) {
	ringDegree := params.N()
	if n < 2 || n >= ringDegree || uint64(n) >= params.PlaintextModulus() {
		return routingLayout{}, fmt.Errorf("n must satisfy 2 <= n < min(N,t)")
	}
	if b <= 0 || n%b != 0 {
		return routingLayout{}, fmt.Errorf("b must be positive and divide n")
	}

	factorCount := n / b
	if factorCount&(factorCount-1) != 0 || ringDegree%factorCount != 0 {
		return routingLayout{}, fmt.Errorf("L=n/b must be a power of two dividing N")
	}
	coefficientGap := ringDegree / factorCount
	if coefficientGap&(coefficientGap-1) != 0 {
		return routingLayout{}, fmt.Errorf("g=N/L must be a power of two")
	}

	return routingLayout{
		n:                 n,
		b:                 b,
		factorCount:       factorCount,
		coefficientGap:    coefficientGap,
		logCoefficientGap: bits.TrailingZeros(uint(coefficientGap)),
	}, nil
}

func newCiphertext(params bgv.Parameters, degree int) *rlwe.Ciphertext {
	ciphertext := bgv.NewCiphertext(params, degree, params.MaxLevel())
	ciphertext.IsBatched = false
	return ciphertext
}

func zeroCiphertext(ciphertext *rlwe.Ciphertext) {
	for component := range ciphertext.Value {
		ciphertext.Value[component].Zero()
	}
}

func newPackingEvaluator(
	params bgv.Parameters,
	galoisKeys []*rlwe.GaloisKey,
) *rlwe.RingPackingEvaluator {
	keySet := rlwe.NewMemEvaluationKeySet(nil, galoisKeys...)
	packingKey := &rlwe.RingPackingEvaluationKey{
		Parameters: map[int]rlwe.ParameterProvider{params.LogN(): params},
		ExtractKeys: map[int]rlwe.EvaluationKeySet{
			params.LogN(): keySet,
		},
	}
	return rlwe.NewRingPackingEvaluator(packingKey)
}
