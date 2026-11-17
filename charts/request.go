package charts

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"runtime"
	"sync"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

// Request is the ciphertext tuple submitted by one sender.
//
// Header encrypts 1,tau,...,tau^n. Control sparsely encrypts tau^(sb), and
// Payloads[r] encrypts tau^r*m(X). Control is omitted when b=n.
type Request struct {
	Header   *rlwe.Ciphertext
	Control  *rlwe.Ciphertext
	Payloads []*rlwe.Ciphertext
}

// PlainRequest is the coefficient-encoded request before encryption.
type PlainRequest struct {
	Header   []uint64
	Control  []uint64
	Payloads [][]uint64
}

// Sender owns one routing secret-key share and the state reused while creating
// requests. A Sender processes one request at a time.
type Sender struct {
	Share     *rlwe.SecretKey
	params    bgv.Parameters
	layout    routingLayout
	field     primeField
	encoder   *bgv.Encoder
	encryptor *rlwe.Encryptor
	plaintext *rlwe.Plaintext
}

// NewSender constructs one input party for the n-sender routing MPC.
func NewSender(
	params bgv.Parameters,
	publicKey *rlwe.PublicKey,
	secretKeyShare *rlwe.SecretKey,
	n int,
	b int,
) (*Sender, error) {
	layout, err := newRoutingLayout(params, n, b)
	if err != nil {
		return nil, err
	}

	plaintext := bgv.NewPlaintext(params, params.MaxLevel())
	plaintext.IsBatched = false
	return &Sender{
		Share:     secretKeyShare,
		params:    params,
		layout:    layout,
		field:     newPrimeField(params.PlaintextModulus()),
		encoder:   bgv.NewEncoder(params),
		encryptor: bgv.NewEncryptor(params, publicKey),
		plaintext: plaintext,
	}, nil
}

// Prepare samples a tag and constructs the clear coefficient vectors.
func (s *Sender) Prepare(message []uint64) (PlainRequest, uint64, error) {
	tag, err := sampleTag(rand.Reader, s.field.modulus)
	if err != nil {
		return PlainRequest{}, 0, err
	}
	request, err := s.PrepareWithTag(tag, message)
	return request, tag, err
}

// PrepareWithTag is the deterministic form used by tests and experiments.
func (s *Sender) PrepareWithTag(
	tag uint64,
	message []uint64,
) (PlainRequest, error) {
	if tag >= s.field.modulus {
		return PlainRequest{}, fmt.Errorf("tag must be in [0,t)")
	}
	if len(message) != s.params.N() {
		return PlainRequest{}, fmt.Errorf("message must contain N=%d coefficients", s.params.N())
	}

	// h_i(X) = sum_{k=0}^{n} tau_i^k X^k.
	header := make([]uint64, s.layout.n+1)
	power := uint64(1)
	for moment := range header {
		header[moment] = power
		power = s.field.mul(power, tag)
	}

	// beta_i(X) = sum_{j=0}^{L-1} tau_i^(jb) X^(jg).
	// When b=n, the payloads already contain every required tag power.
	var control []uint64
	if s.layout.factorCount > 1 {
		control = make([]uint64, s.params.N())
		step := ring.ModExp(tag, uint64(s.layout.b), s.field.modulus)
		power = 1
		for factor := 0; factor < s.layout.factorCount; factor++ {
			control[factor*s.layout.coefficientGap] = power
			power = s.field.mul(power, step)
		}
	}

	// theta_{i,r}(X) = tau_i^r d_i(X).
	payloads := make([][]uint64, s.layout.b)
	power = 1
	for remainder := range payloads {
		payloads[remainder] = make([]uint64, s.params.N())
		for coefficient, value := range message {
			if value >= s.field.modulus {
				value %= s.field.modulus
			}
			payloads[remainder][coefficient] = s.field.mul(power, value)
		}
		power = s.field.mul(power, tag)
	}

	return PlainRequest{Header: header, Control: control, Payloads: payloads}, nil
}

// Encrypts the prepared and formatted request
// PARALLELIZED
func (s *Sender) EncryptPrepared(
	plain PlainRequest,
) (Request, error) {
	payloads := make(
		[]*rlwe.Ciphertext,
		len(plain.Payloads),
	)

	var header *rlwe.Ciphertext
	var control *rlwe.Ciphertext

	/*
		Task layout:

		    0       -> header
		    1       -> control, if present
		    rest    -> payloads
	*/
	taskCount := 1 + len(payloads)

	hasControl := s.layout.factorCount > 1
	if hasControl {
		taskCount++
	}

	workerCount := min(
		runtime.GOMAXPROCS(0),
		taskCount,
	)

	jobs := make(chan int)

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
		wg.Add(1)

		go func() {
			defer wg.Done()

			for job := range jobs {
				if firstErr != nil {
					continue
				}

				switch {
				case job == 0:
					ct, err := s.encrypt(plain.Header)
					if err != nil {
						setErr(err)
						continue
					}

					header = ct

				case hasControl && job == 1:
					ct, err := s.encrypt(plain.Control)
					if err != nil {
						setErr(err)
						continue
					}

					control = ct

				default:
					payloadIndex := job - 1

					if hasControl {
						payloadIndex--
					}

					ct, err := s.encrypt(
						plain.Payloads[payloadIndex],
					)
					if err != nil {
						setErr(err)
						continue
					}

					payloads[payloadIndex] = ct
				}
			}
		}()
	}

	for job := 0; job < taskCount; job++ {
		jobs <- job
	}

	close(jobs)
	wg.Wait()

	if firstErr != nil {
		return Request{}, firstErr
	}

	return Request{
		Header:   header,
		Control:  control,
		Payloads: payloads,
	}, nil
}

// Encrypt prepares and encrypts one full-length message with a sampled tag.
func (s *Sender) Encrypt(message []uint64) (Request, uint64, error) {
	plain, tag, err := s.Prepare(message)
	if err != nil {
		return Request{}, 0, err
	}
	request, err := s.EncryptPrepared(plain)
	return request, tag, err
}

// EncryptWithTag is the deterministic form used by tests and experiments.
func (s *Sender) EncryptWithTag(tag uint64, message []uint64) (Request, error) {
	plain, err := s.PrepareWithTag(tag, message)
	if err != nil {
		return Request{}, err
	}
	return s.EncryptPrepared(plain)
}

func (s *Sender) encrypt(values []uint64) (*rlwe.Ciphertext, error) {
	plaintext := bgv.NewPlaintext(
		s.params,
		s.params.MaxLevel(),
	)
	plaintext.IsBatched = false

	if err := s.encoder.Encode(values, plaintext); err != nil {
		return nil, err
	}

	ciphertext := bgv.NewCiphertext(
		s.params,
		1,
		s.params.MaxLevel(),
	)

	if err := s.encryptor.Encrypt(plaintext, ciphertext); err != nil {
		return nil, err
	}

	return ciphertext, nil
}

func sampleTag(random io.Reader, modulus uint64) (uint64, error) {
	cutoff := -modulus % modulus
	var buffer [8]byte
	for {
		if _, err := io.ReadFull(random, buffer[:]); err != nil {
			return 0, err
		}
		value := binary.LittleEndian.Uint64(buffer[:])
		if value >= cutoff {
			return value % modulus, nil
		}
	}
}
