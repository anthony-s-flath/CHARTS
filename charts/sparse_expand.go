package charts

import (
	"fmt"
	"runtime"
	"sync"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
)

func ExpandSparse(
	eval *rlwe.RingPackingEvaluator,
	ct *rlwe.Ciphertext,
	logGap int,
) (cts map[int]*rlwe.Ciphertext, err error) {
	logN := ct.LogN()
	if logGap < 0 || logGap > logN {
		return nil, fmt.Errorf(
			"logGap=%d must satisfy 0 <= logGap <= logN=%d",
			logGap,
			logN,
		)
	}

	var params rlwe.Parameters
	if p, ok := eval.Parameters[logN]; !ok {
		return nil, fmt.Errorf("eval.Parameters[%d] is nil", logN)
	} else {
		params = *p.GetRLWEParameters()
	}

	var evk rlwe.EvaluationKeySet
	if p, ok := eval.ExtractKeys[params.LogN()]; !ok {
		return nil, fmt.Errorf(
			"eval.ExtractKeys[%d] is nil",
			params.LogN(),
		)
	} else {
		evk = p
	}

	baseEval := eval.Evaluators[params.LogN()]

	xPow2 := eval.XInvPow2NTT[params.LogN()]

	evalN := baseEval.WithKey(evk)

	level := ct.Level()
	ringQ := params.RingQ().AtLevel(level)

	logL := logN - logGap
	L := 1 << logL
	gap := 1 << logGap

	// Internally store only the L ciphertexts CHARTS actually needs.
	work := make([]*rlwe.Ciphertext, L)

	work[0] = ct.CopyNew()
	work[0].LogDimensions = ring.Dimensions{
		Rows: 0,
		Cols: 0,
	}

	if !work[0].IsNTT {
		ringQ.NTT(
			work[0].Value[0],
			work[0].Value[0],
		)
		ringQ.NTT(
			work[0].Value[1],
			work[0].Value[1],
		)

		work[0].IsNTT = true
	}

	// Sparse expansion performs logL doubling levels.
	work[0].Scale = work[0].Scale.Mul(
		rlwe.NewScale(uint64(L)),
	)

	// Each expansion level depends on the previous level,
	// so the outer loop remains sequential.
	for i := logGap; i < logN; i++ {
		n := 1 << i

		// Number of existing ciphertexts entering this level.
		activeCount := n / gap

		/* #nosec G115 -- N and n cannot be negative */
		galEl := uint64(ringQ.N()/n + 1)

		workerCount := min(
			runtime.GOMAXPROCS(0),
			activeCount,
		)

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

		for worker := 0; worker < workerCount; worker++ {
			start := worker * activeCount / workerCount
			end := (worker + 1) * activeCount / workerCount

			wg.Add(1)

			go func(start, end int) {
				defer wg.Done()

				// Each worker needs its own scratch ciphertext.
				tmp := work[0].CopyNew()
				*tmp.MetaData = *work[0].MetaData

				for index := start; index < end; index++ {
					c0 := work[index]

					// X -> X^{N/n + 1}.
					if err := evalN.Automorphism(
						c0,
						galEl,
						tmp,
					); err != nil {
						setErr(fmt.Errorf(
							"evalN.Automorphism: %w",
							err,
						))
						return
					}

					// Clone before modifying c0.
					c1 := c0.CopyNew()

					// Sum branch.
					ringQ.Add(
						c0.Value[0],
						tmp.Value[0],
						c0.Value[0],
					)
					ringQ.Add(
						c0.Value[1],
						tmp.Value[1],
						c0.Value[1],
					)

					// Difference branch.
					ringQ.Sub(
						c1.Value[0],
						tmp.Value[0],
						c1.Value[0],
					)
					ringQ.Sub(
						c1.Value[1],
						tmp.Value[1],
						c1.Value[1],
					)

					// Shift selected coefficient class.
					ringQ.MulCoeffsMontgomery(
						c1.Value[0],
						xPow2[i],
						c1.Value[0],
					)
					ringQ.MulCoeffsMontgomery(
						c1.Value[1],
						xPow2[i],
						c1.Value[1],
					)

					// Second half of this level's output.
					work[index+activeCount] = c1
				}
			}(start, end)
		}

		// Must finish level i before beginning level i+1.
		wg.Wait()

		if firstErr != nil {
			return nil, firstErr
		}
	}

	// Convert back to the sparse map expected by the router.
	cts = make(map[int]*rlwe.Ciphertext, L)

	for index, ciphertext := range work {
		cts[index*gap] = ciphertext
	}

	return cts, nil
}
