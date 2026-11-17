package charts

import "testing"

// These internal tests check layout invariants with a fixed small ring.
// Configured protocol correctness is exercised by the external tests.

func TestRoutingLayout(t *testing.T) {
	params, err := TrivialParameters()
	if err != nil {
		t.Fatal(err)
	}

	layout, err := newRoutingLayout(params, 8, 2)
	if err != nil {
		t.Fatal(err)
	}
	if layout.n != 8 ||
		layout.b != 2 ||
		layout.factorCount != 4 ||
		layout.coefficientGap != params.N()/4 ||
		layout.logCoefficientGap != params.LogN()-2 {
		t.Fatalf("unexpected layout: %+v", layout)
	}
}

func TestDirectRouterOmitsExpansionState(t *testing.T) {
	params, err := TrivialParameters()
	if err != nil {
		t.Fatal(err)
	}

	router, err := NewRouter(params, 8, 8, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if router.pending != nil {
		t.Fatal("direct router allocated degree-two payload accumulators")
	}
	if router.packing != nil {
		t.Fatal("direct router allocated a control-expansion evaluator")
	}
}

func TestSparseExpansionKeySelection(t *testing.T) {
	params, err := TrivialParameters()
	if err != nil {
		t.Fatal(err)
	}

	elements, err := galoisElements(params, 128, 16)
	if err != nil {
		t.Fatal(err)
	}
	if len(elements) != 3 {
		t.Fatalf("paper profile selected %d expansion keys; want log2(n/b)=3", len(elements))
	}

	elements, err = galoisElements(params, PaperN, PaperN)
	if err != nil {
		t.Fatal(err)
	}
	if elements != nil {
		t.Fatalf("direct profile selected %d expansion keys; want none", len(elements))
	}
}

func TestRoutingLayoutRejectsInvalidParameters(t *testing.T) {
	params, err := TrivialParameters()
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		n    int
		b    int
	}{
		{"one sender", 1, 1},
		{"n reaches N", params.N(), params.N()},
		{"zero b", 8, 0},
		{"b does not divide n", 8, 3},
		{"L is not a power of two", 12, 4},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := newRoutingLayout(
				params,
				test.n,
				test.b,
			); err == nil {
				t.Fatal("accepted invalid routing parameters")
			}
		})
	}
}
