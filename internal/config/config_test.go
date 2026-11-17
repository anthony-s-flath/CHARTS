package config

import (
	"math"
	"testing"

	charts "github.com/anthony-s-flath/CHARTS/charts"
)

func TestConfiguration(t *testing.T) {
	cases := []struct {
		name       string
		env        map[string]string
		profile    string
		n, b, logN int
		logQ, logP []int
	}{
		{"defaults", nil, "paper", 128, 128, 13, []int{54, 54, 54}, nil},
		{"paper direct symbolic width", map[string]string{"CHARTS_N": "32", "CHARTS_B": "n"}, "paper", 32, 32, 13, []int{54, 54, 54}, nil},
		{"paper direct numeric width", map[string]string{"CHARTS_N": "32", "CHARTS_B": "32"}, "paper", 32, 32, 13, []int{54, 54, 54}, nil},
		{"paper expanded", map[string]string{"CHARTS_B": "16", "CHARTS_T": "34359754753"}, "paper", 128, 16, 14, []int{50, 50, 50, 45}, []int{50}},
		{"legacy paper expanded", map[string]string{"CHARTS_BENCH_N": "32", "CHARTS_BENCH_B": "16", "CHARTS_T": "34359754753"}, "paper", 32, 16, 14, []int{50, 50, 50, 45}, []int{50}},
		{"expanded overrides", map[string]string{"CHARTS_N": "8", "CHARTS_B": "2", "CHARTS_LOGN": "9", "CHARTS_LOGQ": "50,49,48", "CHARTS_LOGP": "none", "CHARTS_T": "257"}, "paper", 8, 2, 9, []int{50, 49, 48}, nil},
		{"trivial", map[string]string{"CHARTS_PROFILE": "trivial"}, "trivial", 8, 2, 8, []int{55, 52, 52}, []int{51, 51}},
		{"legacy", map[string]string{"CHARTS_BENCH_PROFILE": "trivial", "CHARTS_BENCH_N": "4", "CHARTS_BENCH_B": "4"}, "trivial", 4, 4, 8, []int{55, 52, 52}, []int{51, 51}},
		{"precedence and dynamic width", map[string]string{"CHARTS_PROFILE": "trivial", "CHARTS_BENCH_PROFILE": "bad", "CHARTS_N": "4", "CHARTS_BENCH_N": "6", "CHARTS_B": "n", "CHARTS_BENCH_B": "3"}, "trivial", 4, 4, 8, []int{55, 52, 52}, []int{51, 51}},
		{"modulus overrides", map[string]string{"CHARTS_PROFILE": "trivial", "CHARTS_LOGN": "9", "CHARTS_LOGQ": "50, 49,48", "CHARTS_LOGP": "none"}, "trivial", 8, 2, 9, []int{50, 49, 48}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := load(func(key string) string { return tc.env[key] })
			if err != nil {
				t.Fatal(err)
			}
			if cfg.Profile != tc.profile || cfg.N != tc.n || cfg.B != tc.b || cfg.Params.LogN() != tc.logN {
				t.Fatalf("unexpected config: %s", cfg.String())
			}
			check := func(have, want []int) {
				t.Helper()
				if len(have) != len(want) {
					t.Fatalf("modulus bits: have %v want %v", have, want)
				}
				for i := range have {
					if have[i] != want[i] {
						t.Fatalf("modulus bits: have %v want %v", have, want)
					}
				}
			}
			check(cfg.Params.LogQi(), tc.logQ)
			check(cfg.Params.LogPi(), tc.logP)
		})
	}
}

func TestNoiseAndPlaintextOverrides(t *testing.T) {
	env := map[string]string{"CHARTS_PROFILE": "trivial", "CHARTS_T": "257", "CHARTS_SMUDGING_SECURITY_BITS": "128", "CHARTS_LOG2_ROUTED_NOISE": "20.5"}
	cfg, err := load(func(key string) string { return env[key] })
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Params.PlaintextModulus() != 257 || math.Log2(cfg.Noise.Sigma) != 84.5 || cfg.Noise.Bound != 6*cfg.Noise.Sigma {
		t.Fatal(cfg.String())
	}
}

func TestInvalidConfiguration(t *testing.T) {
	cases := []map[string]string{
		{"CHARTS_PROFILE": "unknown"},
		{"CHARTS_N": "1"},
		{"CHARTS_N": "256"},
		{"CHARTS_B": "0"},
		{"CHARTS_B": "3"},
		{"CHARTS_N": "12", "CHARTS_B": "4"},
		{"CHARTS_LOGN": "-1"},
		{"CHARTS_LOGQ": "61"},
		{"CHARTS_LOGQ": "50,"},
		{"CHARTS_LOGP": "0"},
		{"CHARTS_T": "bad"},
		{"CHARTS_T": "1"},
		{"CHARTS_SMUDGING_SECURITY_BITS": "0"},
		{"CHARTS_LOG2_ROUTED_NOISE": "NaN"},
		{"CHARTS_LOG2_ROUTED_NOISE": "Inf"},
		{"CHARTS_LOG2_ROUTED_NOISE": "-1"},
		{"CHARTS_LOG2_ROUTED_NOISE": "10000"},
	}
	for _, env := range cases {
		if env["CHARTS_PROFILE"] == "" {
			env["CHARTS_PROFILE"] = "trivial"
		}
		if cfg, err := load(func(key string) string { return env[key] }); err == nil {
			t.Fatalf("accepted %v: %s", env, cfg.String())
		}
	}
}

// The optimized circuit has its own compatible plaintext modulus.
func TestPaperExpandedPresetUsesOptimizedPlaintextModulus(t *testing.T) {
	cfg, err := load(func(key string) string {
		if key == "CHARTS_B" {
			return "16"
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Params.PlaintextModulus() != charts.OptimizedPlaintextModulus {
		t.Fatalf("expanded circuit did not select optimized plaintext modulus: %s", cfg.String())
	}
}

func TestRoutingSmudgingDefaultsAndOverride(t *testing.T) {
	for _, tc := range []struct {
		width, override string
		want            float64
	}{
		{"n", "", 72}, {"2", "", 18}, {"n", "21.5", 21.5}, {"2", "21.5", 21.5},
	} {
		env := map[string]string{"CHARTS_PROFILE": "trivial", "CHARTS_N": "4", "CHARTS_B": tc.width, "CHARTS_LOG2_ROUTED_NOISE": tc.override}
		cfg, err := load(func(key string) string { return env[key] })
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Log2RoutedNoise != tc.want || math.Log2(cfg.Noise.Sigma) != float64(cfg.SmudgingSecurityBits)/2+tc.want {
			t.Fatalf("wrong smudging for b=%s override=%q: %s", tc.width, tc.override, cfg.String())
		}
	}
}
