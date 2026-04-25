package keys

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

// HybridPQLevels — все три PQ-уровня для гибрида с ожидаемым итоговым алгоритмом.
// Экспортирован для использования в jwk-тестах.
var HybridPQLevels = []struct {
	PQAlg     Alg
	HybridAlg Alg
}{
	{AlgMLDSA44, AlgHybridECDSAMLDSA44},
	{AlgMLDSA65, AlgHybridECDSAMLDSA65},
	{AlgMLDSA87, AlgHybridECDSAMLDSA87},
}

func TestHybrid_RoundTrip(t *testing.T) {
	t.Parallel()
	for _, lvl := range HybridPQLevels {
		t.Run(string(lvl.PQAlg), func(t *testing.T) {
			t.Parallel()
			priv, err := GenerateHybrid(lvl.PQAlg)
			if err != nil {
				t.Fatalf("GenerateHybrid: %v", err)
			}
			if priv.Algorithm() != lvl.HybridAlg {
				t.Fatalf("alg = %s, want %s", priv.Algorithm(), lvl.HybridAlg)
			}

			msg := []byte("hybrid round-trip " + lvl.PQAlg.String())
			sig, err := priv.Sign(msg)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			pub := priv.Public()
			if err := pub.Verify(msg, sig); err != nil {
				t.Fatalf("Verify: %v", err)
			}
			hybridPub, ok := pub.(*HybridPublicKey)
			if !ok {
				t.Fatalf("pub is %T, want *HybridPublicKey", pub)
			}
			if err := hybridPub.VerifySequential(msg, sig); err != nil {
				t.Fatalf("VerifySequential: %v", err)
			}
		})
	}
}

func TestHybrid_TamperedClassicComponent(t *testing.T) {
	t.Parallel()
	priv, _ := GenerateHybrid(AlgMLDSA65)
	msg := []byte("tamper classic")
	sig, _ := priv.Sign(msg)

	classicLen := int(binary.BigEndian.Uint16(sig[:2]))
	tampered := bytes.Clone(sig)
	tampered[2+classicLen-1] ^= 0x01

	if err := priv.Public().Verify(msg, tampered); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("Verify(tampered classic) error = %v, want ErrInvalidSignature", err)
	}
}

func TestHybrid_TamperedPQComponent(t *testing.T) {
	t.Parallel()
	priv, _ := GenerateHybrid(AlgMLDSA65)
	msg := []byte("tamper pq")
	sig, _ := priv.Sign(msg)

	tampered := bytes.Clone(sig)
	tampered[len(tampered)-1] ^= 0x01

	if err := priv.Public().Verify(msg, tampered); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("Verify(tampered pq) error = %v, want ErrInvalidSignature", err)
	}
}

func TestHybrid_AlgMismatch(t *testing.T) {
	t.Parallel()
	pq, _ := GenerateMLDSA(AlgMLDSA65)
	classicWrong, _ := GenerateMLDSA(AlgMLDSA44)
	if _, err := NewHybrid(classicWrong, pq); !errors.Is(err, ErrAlgMismatch) {
		t.Errorf("NewHybrid(non-ecdsa, pq) error = %v, want ErrAlgMismatch", err)
	}
	classic, _ := GenerateECDSA()
	pqWrong, _ := GenerateECDSA()
	if _, err := NewHybrid(classic, pqWrong); !errors.Is(err, ErrAlgMismatch) {
		t.Errorf("NewHybrid(ecdsa, ecdsa) error = %v, want ErrAlgMismatch", err)
	}
}

func TestHybrid_MalformedSignature(t *testing.T) {
	t.Parallel()
	priv, _ := GenerateHybrid(AlgMLDSA65)
	pub := priv.Public()

	cases := map[string][]byte{
		"too short":           {0x00},
		"zero classic length": append([]byte{0x00, 0x00}, []byte("payload")...),
		"length exceeds total": func() []byte {
			b := make([]byte, 4)
			binary.BigEndian.PutUint16(b[:2], 9999)
			return b
		}(),
		"missing pq part": func() []byte {
			b := make([]byte, 2+72)
			binary.BigEndian.PutUint16(b[:2], 72)
			return b
		}(),
	}
	for name, sig := range cases {
		t.Run(name, func(t *testing.T) {
			err := pub.Verify([]byte("msg"), sig)
			if !errors.Is(err, ErrMalformedSignature) {
				t.Errorf("Verify(%s) error = %v, want ErrMalformedSignature", name, err)
			}
		})
	}
}

func TestHybrid_Components(t *testing.T) {
	t.Parallel()
	priv, _ := GenerateHybrid(AlgMLDSA65)
	classicPriv, pqPriv := priv.Components()
	if classicPriv.Algorithm() != AlgECDSAP256 {
		t.Errorf("classic alg = %s, want %s", classicPriv.Algorithm(), AlgECDSAP256)
	}
	if pqPriv.Algorithm() != AlgMLDSA65 {
		t.Errorf("pq alg = %s, want %s", pqPriv.Algorithm(), AlgMLDSA65)
	}

	pub, ok := priv.Public().(*HybridPublicKey)
	if !ok {
		t.Fatalf("priv.Public() is not *HybridPublicKey")
	}
	classicPub, pqPub := pub.Components()
	if classicPub.Algorithm() != AlgECDSAP256 || pqPub.Algorithm() != AlgMLDSA65 {
		t.Errorf("public components have wrong algorithms: %s, %s",
			classicPub.Algorithm(), pqPub.Algorithm())
	}
}

func BenchmarkHybrid_Keygen(b *testing.B) {
	for _, lvl := range HybridPQLevels {
		b.Run(string(lvl.PQAlg), func(b *testing.B) {
			b.ReportAllocs()
			for range b.N {
				if _, err := GenerateHybrid(lvl.PQAlg); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkHybrid_Sign(b *testing.B) {
	for _, lvl := range HybridPQLevels {
		b.Run(string(lvl.PQAlg), func(b *testing.B) {
			priv, _ := GenerateHybrid(lvl.PQAlg)
			msg := []byte("benchmark hybrid sign")
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

// BenchmarkHybrid_VerifyParallel — основной режим (errgroup).
func BenchmarkHybrid_VerifyParallel(b *testing.B) {
	for _, lvl := range HybridPQLevels {
		b.Run(string(lvl.PQAlg), func(b *testing.B) {
			priv, _ := GenerateHybrid(lvl.PQAlg)
			msg := []byte("benchmark hybrid verify parallel")
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

// BenchmarkHybrid_VerifySequential — для сравнения с параллельным
// (раздел 4.4 диссертации).
func BenchmarkHybrid_VerifySequential(b *testing.B) {
	for _, lvl := range HybridPQLevels {
		b.Run(string(lvl.PQAlg), func(b *testing.B) {
			priv, _ := GenerateHybrid(lvl.PQAlg)
			msg := []byte("benchmark hybrid verify sequential")
			sig, _ := priv.Sign(msg)
			pub := priv.Public().(*HybridPublicKey)
			b.ResetTimer()
			b.ReportAllocs()
			for range b.N {
				if err := pub.VerifySequential(msg, sig); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
