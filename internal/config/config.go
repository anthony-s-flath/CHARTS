// Package config supplies one environment interface for experiments.
// Protocol tests, benchmarks, noise tests, and commands share these settings.
package config

import (
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"

	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"

	charts "github.com/anthony-s-flath/CHARTS/charts"
)

type Config struct {
	Profile              string
	Params               bgv.Parameters
	N, B                 int
	Noise                ring.DiscreteGaussian
	SmudgingSecurityBits int
	Log2RoutedNoise      float64
}

// Load reads CHARTS_* settings. CHARTS_BENCH_{PROFILE,N,B} remain fallback
// aliases; canonical names take precedence. B=n is resolved after N.
func Load() (Config, error) { return load(os.Getenv) }

func load(getenv func(string) string) (Config, error) {
	value := func(name, fallback string) string {
		if v := strings.TrimSpace(getenv("CHARTS_" + name)); v != "" {
			return v
		}
		switch name {
		case "PROFILE", "N", "B":
			if v := strings.TrimSpace(getenv("CHARTS_BENCH_" + name)); v != "" {
				return v
			}
		}
		return fallback
	}
	cfg := Config{Profile: strings.ToLower(value("PROFILE", "paper"))}
	var err error
	defaultN, defaultB := charts.PaperN, charts.PaperB
	if cfg.Profile == "trivial" {
		defaultN, defaultB = charts.TrivialN, charts.TrivialB
	}
	integer := func(name string, fallback, low, high int) (int, error) {
		raw := value(name, strconv.Itoa(fallback))
		v, err := strconv.Atoi(raw)
		if err != nil || v < low || v > high {
			return 0, fmt.Errorf("CHARTS_%s=%q must be an integer in [%d,%d]", name, raw, low, high)
		}
		return v, nil
	}
	cfg.N, err = integer("N", defaultN, 2, 1<<20)
	if err != nil {
		return Config{}, err
	}
	if strings.EqualFold(value("B", ""), "n") {
		cfg.B = cfg.N
	} else {
		cfg.B, err = integer("B", defaultB, 1, cfg.N)
		if err != nil {
			return Config{}, err
		}
	}
	// Resolve dimensions first: the paper preset depends on the actual B,
	// including B=n and the legacy environment aliases.
	literal, err := charts.ParameterLiteralForRouting(cfg.Profile, cfg.N, cfg.B)
	if err != nil {
		return Config{}, err
	}
	literal.LogN, err = integer("LOGN", literal.LogN, 4, 20)
	if err != nil {
		return Config{}, err
	}
	if raw := value("LOGQ", ""); raw != "" {
		literal.LogQ, err = modulusBits("CHARTS_LOGQ", raw, false)
		if err != nil {
			return Config{}, err
		}
	}
	if raw := value("LOGP", ""); raw != "" {
		literal.LogP, err = modulusBits("CHARTS_LOGP", raw, true)
		if err != nil {
			return Config{}, err
		}
	}
	if raw := value("T", ""); raw != "" {
		literal.PlaintextModulus, err = strconv.ParseUint(raw, 10, 64)
		if err != nil || literal.PlaintextModulus < 2 {
			return Config{}, fmt.Errorf("CHARTS_T=%q must be a uint64 greater than one", raw)
		}
	}
	cfg.Params, err = bgv.NewParametersFromLiteral(literal)
	if err != nil {
		return Config{}, fmt.Errorf("BGV parameters: %w", err)
	}
	// Validate the same layout invariants as the routing library, before setup.
	if cfg.N >= cfg.Params.N() || uint64(cfg.N) >= cfg.Params.PlaintextModulus() {
		return Config{}, fmt.Errorf("n must satisfy 2 <= n < min(N,t)")
	}
	if cfg.N%cfg.B != 0 {
		return Config{}, fmt.Errorf("b must divide n")
	}
	factors := cfg.N / cfg.B
	if factors&(factors-1) != 0 || cfg.Params.N()%factors != 0 {
		return Config{}, fmt.Errorf("L=n/b must be a power of two dividing N")
	}
	cfg.SmudgingSecurityBits, err = integer("SMUDGING_SECURITY_BITS", charts.DefaultSmudgingSecurityBits, 1, 1024)
	if err != nil {
		return Config{}, err
	}
	raw := value(
		"LOG2_ROUTED_NOISE",
		strconv.Itoa(charts.DefaultLog2RoutedNoiseForRouting(cfg.N, cfg.B)),
	)
	cfg.Log2RoutedNoise, err = strconv.ParseFloat(raw, 64)
	if err != nil || math.IsNaN(cfg.Log2RoutedNoise) || math.IsInf(cfg.Log2RoutedNoise, 0) || cfg.Log2RoutedNoise < 0 {
		return Config{}, fmt.Errorf("CHARTS_LOG2_ROUTED_NOISE=%q must be finite and nonnegative", raw)
	}
	sigma := math.Exp2(float64(cfg.SmudgingSecurityBits)/2 + cfg.Log2RoutedNoise)
	if math.IsInf(6*sigma, 0) {
		return Config{}, fmt.Errorf("configured smudging distribution overflows float64")
	}
	cfg.Noise = ring.DiscreteGaussian{Sigma: sigma, Bound: 6 * sigma}
	return cfg, nil
}

func modulusBits(name, raw string, allowNone bool) ([]int, error) {
	if allowNone && strings.EqualFold(raw, "none") {
		return nil, nil
	}
	parts := strings.Split(raw, ",")
	result := make([]int, len(parts))
	for i, part := range parts {
		v, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil || v < 1 || v > 60 {
			return nil, fmt.Errorf("%s=%q must be comma-separated bit sizes in [1,60]", name, raw)
		}
		result[i] = v
	}
	return result, nil
}

// String reports the effective parameters, including overrides, in run logs.
func (c Config) String() string {
	return fmt.Sprintf("profile=%s n=%d b=%d L=%d LogN=%d LogQ=%v LogP=%v t=%d smudging-bits=%d log2(routed-noise)=%g log2(sigma)=%g",
		c.Profile, c.N, c.B, c.N/c.B, c.Params.LogN(), c.Params.LogQi(), c.Params.LogPi(),
		c.Params.PlaintextModulus(), c.SmudgingSecurityBits, c.Log2RoutedNoise, math.Log2(c.Noise.Sigma))
}
