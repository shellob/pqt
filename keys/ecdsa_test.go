package keys

import (
	"bytes"
	"errors"
	"testing"
)

func TestECDSA_RoundTrip(t *testing.T) {
	t.Parallel()
	priv, err := GenerateECDSA()
	if err != nil {
		t.Fatalf("GenerateECDSA: %v", err)
	}
	if priv.Algorithm() != AlgECDSAP256 {
		t.Fatalf("alg = %s, want %s", priv.Algorithm(), AlgECDSAP256)
	}

	msg := []byte("post-quantum access token: round-trip")
	sig, err := priv.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if got := len(sig); got < 64 || got > 80 {
		t.Errorf("ecdsa signature size = %d, want 64–80", got)
	}

	pub := priv.Public()
	if pub.Algorithm() != AlgECDSAP256 {
		t.Fatalf("pub alg = %s, want %s", pub.Algorithm(), AlgECDSAP256)
	}
	if err := pub.Verify(msg, sig); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestECDSA_TamperedSignature(t *testing.T) {
	t.Parallel()
	priv, _ := GenerateECDSA()
	msg := []byte("tamper test")
	sig, _ := priv.Sign(msg)

	tampered := bytes.Clone(sig)
	tampered[len(tampered)-1] ^= 0x01

	err := priv.Public().Verify(msg, tampered)
	if !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("Verify(tampered) error = %v, want ErrInvalidSignature", err)
	}
}

func TestECDSA_TamperedMessage(t *testing.T) {
	t.Parallel()
	priv, _ := GenerateECDSA()
	msg := []byte("original message")
	sig, _ := priv.Sign(msg)

	err := priv.Public().Verify([]byte("modified message"), sig)
	if !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("Verify(other msg) error = %v, want ErrInvalidSignature", err)
	}
}

func TestECDSA_WrongKey(t *testing.T) {
	t.Parallel()
	priv1, _ := GenerateECDSA()
	priv2, _ := GenerateECDSA()

	msg := []byte("cross-key test")
	sig, _ := priv1.Sign(msg)

	if err := priv2.Public().Verify(msg, sig); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("Verify with wrong key: err = %v, want ErrInvalidSignature", err)
	}
}

func TestECDSA_PrivateScalar_RoundTrip(t *testing.T) {
	t.Parallel()
	priv1, _ := GenerateECDSA()
	scalar, err := priv1.PrivateScalar()
	if err != nil {
		t.Fatalf("PrivateScalar: %v", err)
	}
	priv2, err := NewECDSAPrivateFromScalar(scalar)
	if err != nil {
		t.Fatalf("NewECDSAPrivateFromScalar: %v", err)
	}
	msg := []byte("scalar round-trip")
	sig1, _ := priv1.Sign(msg)
	if err := priv2.Public().Verify(msg, sig1); err != nil {
		t.Fatalf("Verify with reconstructed key: %v", err)
	}
}

func TestECDSA_PublicBytes_RoundTrip(t *testing.T) {
	t.Parallel()
	priv, _ := GenerateECDSA()
	pubBytes, err := priv.PublicBytes()
	if err != nil {
		t.Fatalf("PublicBytes: %v", err)
	}
	pub, err := NewECDSAPublicFromUncompressed(pubBytes)
	if err != nil {
		t.Fatalf("NewECDSAPublicFromUncompressed: %v", err)
	}
	msg := []byte("public bytes round-trip")
	sig, _ := priv.Sign(msg)
	if err := pub.Verify(msg, sig); err != nil {
		t.Fatalf("Verify with reconstructed public: %v", err)
	}
}

func BenchmarkECDSA_Keygen(b *testing.B) {
	b.ReportAllocs()
	for range b.N {
		if _, err := GenerateECDSA(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkECDSA_Sign(b *testing.B) {
	priv, _ := GenerateECDSA()
	msg := []byte("benchmark message for ecdsa sign")
	b.ResetTimer()
	b.ReportAllocs()
	for range b.N {
		if _, err := priv.Sign(msg); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkECDSA_Verify(b *testing.B) {
	priv, _ := GenerateECDSA()
	msg := []byte("benchmark message for ecdsa verify")
	sig, _ := priv.Sign(msg)
	pub := priv.Public()
	b.ResetTimer()
	b.ReportAllocs()
	for range b.N {
		if err := pub.Verify(msg, sig); err != nil {
			b.Fatal(err)
		}
	}
}
