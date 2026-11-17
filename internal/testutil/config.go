package testutil

import (
	"testing"

	"github.com/anthony-s-flath/CHARTS/internal/config"
)

// LoadConfig uses exactly the same settings as the benchmark and noise test.
// No smaller ring, batch, or flooding distribution is substituted in tests.
func LoadConfig(t testing.TB) config.Config {
	t.Helper()
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	t.Log(cfg.String())
	return cfg
}
