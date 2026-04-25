package keys

import "testing"

func TestAlg_Valid(t *testing.T) {
	t.Parallel()
	cases := []struct {
		alg   Alg
		valid bool
	}{
		{AlgECDSAP256, true},
		{AlgMLDSA44, true},
		{AlgMLDSA65, true},
		{AlgMLDSA87, true},
		{AlgHybridECDSAMLDSA44, true},
		{AlgHybridECDSAMLDSA65, true},
		{AlgHybridECDSAMLDSA87, true},
		{Alg("hs256"), false},
		{Alg(""), false},
		{Alg("MLDSA65"), false}, // регистр важен
	}
	for _, tc := range cases {
		if got := tc.alg.Valid(); got != tc.valid {
			t.Errorf("Alg(%q).Valid() = %v, want %v", tc.alg, got, tc.valid)
		}
	}
}

func TestAlg_IsHybrid(t *testing.T) {
	t.Parallel()
	cases := []struct {
		alg    Alg
		hybrid bool
	}{
		{AlgECDSAP256, false},
		{AlgMLDSA65, false},
		{AlgHybridECDSAMLDSA44, true},
		{AlgHybridECDSAMLDSA65, true},
		{AlgHybridECDSAMLDSA87, true},
	}
	for _, tc := range cases {
		if got := tc.alg.IsHybrid(); got != tc.hybrid {
			t.Errorf("Alg(%q).IsHybrid() = %v, want %v", tc.alg, got, tc.hybrid)
		}
	}
}
