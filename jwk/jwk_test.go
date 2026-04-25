package jwk_test

import (
	"encoding/json"
	"errors"
	"testing"

	"pqt/jwk"
	"pqt/keys"
)

func TestJWK_RoundTrip_ECDSA(t *testing.T) {
	t.Parallel()

	priv, err := keys.GenerateECDSA()
	if err != nil {
		t.Fatalf("GenerateECDSA: %v", err)
	}

	privJWK, err := jwk.MarshalPrivate(priv)
	if err != nil {
		t.Fatalf("MarshalPrivate: %v", err)
	}
	if privJWK.Kty != "EC" || privJWK.Crv != "P-256" || privJWK.D == "" {
		t.Fatalf("private JWK = %+v", privJWK)
	}

	parsedPriv, err := jwk.ParsePrivate(privJWK)
	if err != nil {
		t.Fatalf("ParsePrivate: %v", err)
	}
	verifyRoundTrip(t, priv, parsedPriv)

	pubJWK, err := jwk.MarshalPublic(priv.Public())
	if err != nil {
		t.Fatalf("MarshalPublic: %v", err)
	}
	if pubJWK.D != "" {
		t.Fatalf("public JWK leaks d field")
	}

	parsedPub, err := jwk.ParsePublic(pubJWK)
	if err != nil {
		t.Fatalf("ParsePublic: %v", err)
	}

	msg := []byte("jwk round-trip ecdsa")
	sig, _ := priv.Sign(msg)
	if err := parsedPub.Verify(msg, sig); err != nil {
		t.Fatalf("Verify with parsed public key: %v", err)
	}
}

// mldsaLevels и hybridPQLevels — локальные списки алгоритмов. Не зависим
// от тестовых таблиц пакета keys, чтобы пакеты были полностью изолированы.
var mldsaLevels = []keys.Alg{keys.AlgMLDSA44, keys.AlgMLDSA65, keys.AlgMLDSA87}

var hybridPQLevels = []keys.Alg{keys.AlgMLDSA44, keys.AlgMLDSA65, keys.AlgMLDSA87}

func TestJWK_RoundTrip_MLDSA(t *testing.T) {
	t.Parallel()
	for _, alg := range mldsaLevels {
		t.Run(string(alg), func(t *testing.T) {
			t.Parallel()

			priv, _ := keys.GenerateMLDSA(alg)

			privJWK, err := jwk.MarshalPrivate(priv)
			if err != nil {
				t.Fatalf("MarshalPrivate: %v", err)
			}
			if privJWK.Kty != "MLDSA" || privJWK.Alg != string(alg) {
				t.Fatalf("priv JWK = %+v", privJWK)
			}
			if privJWK.Pub == "" || privJWK.Priv == "" {
				t.Fatalf("priv JWK missing pub or priv")
			}

			parsedPriv, err := jwk.ParsePrivate(privJWK)
			if err != nil {
				t.Fatalf("ParsePrivate: %v", err)
			}
			verifyRoundTrip(t, priv, parsedPriv)

			pubJWK, err := jwk.MarshalPublic(priv.Public())
			if err != nil {
				t.Fatalf("MarshalPublic: %v", err)
			}
			if pubJWK.Priv != "" {
				t.Fatalf("public JWK leaks priv field")
			}
			parsedPub, err := jwk.ParsePublic(pubJWK)
			if err != nil {
				t.Fatalf("ParsePublic: %v", err)
			}
			msg := []byte("jwk round-trip " + alg.String())
			sig, _ := priv.Sign(msg)
			if err := parsedPub.Verify(msg, sig); err != nil {
				t.Fatalf("Verify with parsed public key: %v", err)
			}
		})
	}
}

func TestJWK_RoundTrip_Hybrid(t *testing.T) {
	t.Parallel()
	for _, pqAlg := range hybridPQLevels {
		t.Run(string(pqAlg), func(t *testing.T) {
			t.Parallel()
			priv, _ := keys.GenerateHybrid(pqAlg)

			privJWK, err := jwk.MarshalPrivate(priv)
			if err != nil {
				t.Fatalf("MarshalPrivate: %v", err)
			}
			if privJWK.Kty != "Hybrid" || len(privJWK.Components) != 2 {
				t.Fatalf("hybrid priv JWK = %+v", privJWK)
			}
			if privJWK.Components[0].D == "" || privJWK.Components[1].Priv == "" {
				t.Fatalf("hybrid priv JWK components missing private material")
			}

			parsedPriv, err := jwk.ParsePrivate(privJWK)
			if err != nil {
				t.Fatalf("ParsePrivate: %v", err)
			}
			verifyRoundTrip(t, priv, parsedPriv)

			pubJWK, _ := jwk.MarshalPublic(priv.Public())
			if pubJWK.Components[0].D != "" || pubJWK.Components[1].Priv != "" {
				t.Fatalf("hybrid public JWK leaks private material")
			}
			parsedPub, err := jwk.ParsePublic(pubJWK)
			if err != nil {
				t.Fatalf("ParsePublic: %v", err)
			}
			msg := []byte("jwk hybrid " + pqAlg.String())
			sig, _ := priv.Sign(msg)
			if err := parsedPub.Verify(msg, sig); err != nil {
				t.Fatalf("Verify with parsed public hybrid: %v", err)
			}
		})
	}
}

func TestJWK_JSONRoundTrip(t *testing.T) {
	t.Parallel()
	priv, _ := keys.GenerateHybrid(keys.AlgMLDSA65)
	j, _ := jwk.MarshalPrivate(priv)

	data, err := json.Marshal(j)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	var roundTripped jwk.JWK
	if err := json.Unmarshal(data, &roundTripped); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	parsed, err := jwk.ParsePrivate(roundTripped)
	if err != nil {
		t.Fatalf("ParsePrivate after JSON: %v", err)
	}
	verifyRoundTrip(t, priv, parsed)
}

func TestJWK_UnsupportedKty(t *testing.T) {
	t.Parallel()
	if _, err := jwk.ParsePrivate(jwk.JWK{Kty: "OKP"}); err == nil {
		t.Errorf("ParsePrivate(OKP) error = nil, want non-nil")
	}
	if _, err := jwk.ParsePublic(jwk.JWK{Kty: "OKP"}); err == nil {
		t.Errorf("ParsePublic(OKP) error = nil, want non-nil")
	}
}

func TestJWK_InvalidECCurve(t *testing.T) {
	t.Parallel()
	_, err := jwk.ParsePrivate(jwk.JWK{Kty: "EC", Crv: "P-384"})
	if !errors.Is(err, keys.ErrUnsupportedAlg) {
		t.Errorf("ParsePrivate(P-384) error = %v, want ErrUnsupportedAlg", err)
	}
}

// verifyRoundTrip — общий хелпер: оригинал подписывает, восстановленная пара
// верифицирует, и наоборот.
func verifyRoundTrip(t *testing.T, original, parsed keys.PrivateKey) {
	t.Helper()
	if original.Algorithm() != parsed.Algorithm() {
		t.Fatalf("algorithm mismatch after round-trip: %s vs %s",
			original.Algorithm(), parsed.Algorithm())
	}
	msg := []byte("verify round-trip helper message")

	sig1, err := original.Sign(msg)
	if err != nil {
		t.Fatalf("original.Sign: %v", err)
	}
	if err := parsed.Public().Verify(msg, sig1); err != nil {
		t.Fatalf("parsed.Public().Verify: %v", err)
	}

	sig2, err := parsed.Sign(msg)
	if err != nil {
		t.Fatalf("parsed.Sign: %v", err)
	}
	if err := original.Public().Verify(msg, sig2); err != nil {
		t.Fatalf("original.Public().Verify(parsed.Sign): %v", err)
	}
}
