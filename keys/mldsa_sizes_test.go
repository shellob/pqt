package keys_test

import (
	"testing"

	"pqt/keys"
)

// TestMLDSASignatureSizes печатает реальные размеры подписей и публичных
// ключей для каждого уровня ML-DSA. Это не бенчмарк по времени, но цифры
// нужны в той же таблице 4.2 диссертации.
func TestMLDSASignatureSizes(t *testing.T) {
	for _, alg := range []keys.Alg{keys.AlgMLDSA44, keys.AlgMLDSA65, keys.AlgMLDSA87} {
		priv, err := keys.GenerateMLDSA(alg)
		if err != nil {
			t.Fatalf("%s: %v", alg, err)
		}
		sig, err := priv.Sign([]byte("size probe"))
		if err != nil {
			t.Fatalf("%s sign: %v", alg, err)
		}
		pubBytes, err := priv.PublicBytes()
		if err != nil {
			t.Fatalf("%s pub bytes: %v", alg, err)
		}
		t.Logf("%-9s подпись=%d байт, публичный ключ=%d байт", alg, len(sig), len(pubBytes))
	}
}
