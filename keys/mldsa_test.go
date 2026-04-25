package keys

import (
	"bytes"
	"errors"
	"testing"
)

// MLDSALevels — все три уровня ML-DSA с ожидаемыми размерами публичного
// ключа и подписи (FIPS 204). Экспортирован для использования в jwk-тестах.
var MLDSALevels = []struct {
	Alg     Alg
	PubSize int
	SigSize int
}{
	{AlgMLDSA44, 1312, 2420},
	{AlgMLDSA65, 1952, 3309},
	{AlgMLDSA87, 2592, 4627},
}

func TestMLDSA_RoundTrip(t *testing.T) {
	t.Parallel()
	for _, lvl := range MLDSALevels {
		t.Run(string(lvl.Alg), func(t *testing.T) {
			t.Parallel()
			priv, err := GenerateMLDSA(lvl.Alg)
			if err != nil {
				t.Fatalf("GenerateMLDSA: %v", err)
			}
			if priv.Algorithm() != lvl.Alg {
				t.Fatalf("alg = %s, want %s", priv.Algorithm(), lvl.Alg)
			}

			msg := []byte("post-quantum access token: " + lvl.Alg.String())
			sig, err := priv.Sign(msg)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			if got := len(sig); got != lvl.SigSize {
				t.Errorf("signature size = %d, want %d", got, lvl.SigSize)
			}

			pub := priv.Public()
			if pub.Algorithm() != lvl.Alg {
				t.Fatalf("pub alg = %s, want %s", pub.Algorithm(), lvl.Alg)
			}
			if err := pub.Verify(msg, sig); err != nil {
				t.Fatalf("Verify: %v", err)
			}
		})
	}
}

func TestMLDSA_TamperedSignature(t *testing.T) {
	t.Parallel()
	priv, _ := GenerateMLDSA(AlgMLDSA65)
	msg := []byte("tamper test")
	sig, _ := priv.Sign(msg)

	tampered := bytes.Clone(sig)
	tampered[len(tampered)-1] ^= 0x01

	err := priv.Public().Verify(msg, tampered)
	if !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("Verify(tampered) error = %v, want ErrInvalidSignature", err)
	}
}

func TestMLDSA_WrongKey(t *testing.T) {
	t.Parallel()
	priv1, _ := GenerateMLDSA(AlgMLDSA65)
	priv2, _ := GenerateMLDSA(AlgMLDSA65)
	msg := []byte("cross-key test")
	sig, _ := priv1.Sign(msg)

	if err := priv2.Public().Verify(msg, sig); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("Verify with wrong key: err = %v, want ErrInvalidSignature", err)
	}
}

func TestMLDSA_UnsupportedAlg(t *testing.T) {
	t.Parallel()
	_, err := GenerateMLDSA(AlgECDSAP256)
	if !errors.Is(err, ErrUnsupportedAlg) {
		t.Fatalf("GenerateMLDSA(ECDSA) error = %v, want ErrUnsupportedAlg", err)
	}
}

func TestMLDSA_PrivateBytes_RoundTrip(t *testing.T) {
	t.Parallel()
	for _, lvl := range MLDSALevels {
		t.Run(string(lvl.Alg), func(t *testing.T) {
			t.Parallel()
			priv1, _ := GenerateMLDSA(lvl.Alg)
			privBytes, err := priv1.PrivateBytes()
			if err != nil {
				t.Fatalf("PrivateBytes: %v", err)
			}
			priv2, err := NewMLDSAPrivateFromBytes(lvl.Alg, privBytes)
			if err != nil {
				t.Fatalf("NewMLDSAPrivateFromBytes: %v", err)
			}
			msg := []byte("private bytes round-trip")
			sig, _ := priv1.Sign(msg)
			if err := priv2.Public().Verify(msg, sig); err != nil {
				t.Fatalf("Verify with reconstructed key: %v", err)
			}
		})
	}
}

func TestMLDSA_PublicBytes_RoundTrip(t *testing.T) {
	t.Parallel()
	for _, lvl := range MLDSALevels {
		t.Run(string(lvl.Alg), func(t *testing.T) {
			t.Parallel()
			priv, _ := GenerateMLDSA(lvl.Alg)
			pubBytes, err := priv.PublicBytes()
			if err != nil {
				t.Fatalf("PublicBytes: %v", err)
			}
			if got := len(pubBytes); got != lvl.PubSize {
				t.Errorf("public size = %d, want %d", got, lvl.PubSize)
			}
			pub, err := NewMLDSAPublicFromBytes(lvl.Alg, pubBytes)
			if err != nil {
				t.Fatalf("NewMLDSAPublicFromBytes: %v", err)
			}
			msg := []byte("public bytes round-trip")
			sig, _ := priv.Sign(msg)
			if err := pub.Verify(msg, sig); err != nil {
				t.Fatalf("Verify with reconstructed public: %v", err)
			}
		})
	}
}

func BenchmarkMLDSA_Keygen(b *testing.B) {
	for _, lvl := range MLDSALevels {
		b.Run(string(lvl.Alg), func(b *testing.B) {
			b.ReportAllocs()
			for range b.N {
				if _, err := GenerateMLDSA(lvl.Alg); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkMLDSA_Sign(b *testing.B) {
	for _, lvl := range MLDSALevels {
		b.Run(string(lvl.Alg), func(b *testing.B) {
			priv, _ := GenerateMLDSA(lvl.Alg)
			msg := []byte("benchmark message for ml-dsa sign")
			b.ResetTimer()
			b.ReportAllocs()
			for range b.N {
				if _, err := priv.Sign(msg); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkMLDSA_Verify(b *testing.B) {
	for _, lvl := range MLDSALevels {
		b.Run(string(lvl.Alg), func(b *testing.B) {
			priv, _ := GenerateMLDSA(lvl.Alg)
			msg := []byte("benchmark message for ml-dsa verify")
			sig, _ := priv.Sign(msg)
			pub := priv.Public()
			b.ResetTimer()
			b.ReportAllocs()
			for range b.N {
				if err := pub.Verify(msg, sig); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
