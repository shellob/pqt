package jwk_test

import (
	"encoding/json"
	"reflect"
	"testing"

	"pqt/jwk"
	"pqt/keys"
)

// makePublicJWK генерирует свежий ключ заданного алгоритма и сразу же
// сериализует его публичную часть в JWK, проставляя kid.
func makePublicJWK(t *testing.T, alg keys.Alg, kid string) jwk.JWK {
	t.Helper()

	var pub keys.PublicKey
	switch alg {
	case keys.AlgECDSAP256:
		priv, err := keys.GenerateECDSA()
		if err != nil {
			t.Fatalf("GenerateECDSA: %v", err)
		}
		pub = priv.Public()
	case keys.AlgMLDSA44, keys.AlgMLDSA65, keys.AlgMLDSA87:
		priv, err := keys.GenerateMLDSA(alg)
		if err != nil {
			t.Fatalf("GenerateMLDSA(%s): %v", alg, err)
		}
		pub = priv.Public()
	case keys.AlgHybridECDSAMLDSA44, keys.AlgHybridECDSAMLDSA65, keys.AlgHybridECDSAMLDSA87:
		var pqAlg keys.Alg
		switch alg {
		case keys.AlgHybridECDSAMLDSA44:
			pqAlg = keys.AlgMLDSA44
		case keys.AlgHybridECDSAMLDSA65:
			pqAlg = keys.AlgMLDSA65
		case keys.AlgHybridECDSAMLDSA87:
			pqAlg = keys.AlgMLDSA87
		}
		priv, err := keys.GenerateHybrid(pqAlg)
		if err != nil {
			t.Fatalf("GenerateHybrid(%s): %v", pqAlg, err)
		}
		pub = priv.Public()
	default:
		t.Fatalf("неизвестный alg %s", alg)
	}

	j, err := jwk.MarshalPublic(pub)
	if err != nil {
		t.Fatalf("MarshalPublic(%s): %v", alg, err)
	}
	j.Kid = kid
	return j
}

func TestJWKSet_FindExistingKid(t *testing.T) {
	t.Parallel()

	set := jwk.Set{
		Keys: []jwk.JWK{
			makePublicJWK(t, keys.AlgECDSAP256, "ec-2026-01"),
			makePublicJWK(t, keys.AlgMLDSA65, "mldsa-2026-04"),
			makePublicJWK(t, keys.AlgHybridECDSAMLDSA65, "hybrid-2026-04"),
		},
	}

	cases := []struct {
		kid     string
		wantKty string
	}{
		{"ec-2026-01", "EC"},
		{"mldsa-2026-04", "MLDSA"},
		{"hybrid-2026-04", "Hybrid"},
	}
	for _, tc := range cases {
		t.Run(tc.kid, func(t *testing.T) {
			t.Parallel()
			got, ok := set.Find(tc.kid)
			if !ok {
				t.Fatalf("ожидали найти ключ с kid=%q, но не нашли", tc.kid)
			}
			if got.Kty != tc.wantKty {
				t.Fatalf("kid=%q: ожидали kty=%q, получили %q", tc.kid, tc.wantKty, got.Kty)
			}
			if got.Kid != tc.kid {
				t.Fatalf("у найденного ключа kid=%q, ожидали %q", got.Kid, tc.kid)
			}
		})
	}
}

func TestJWKSet_FindMissingKid(t *testing.T) {
	t.Parallel()

	set := jwk.Set{
		Keys: []jwk.JWK{
			makePublicJWK(t, keys.AlgECDSAP256, "ec-2026-01"),
		},
	}

	if _, ok := set.Find("nope"); ok {
		t.Fatal("ожидали false для несуществующего kid")
	}
}

func TestJWKSet_FindEmptyKid(t *testing.T) {
	t.Parallel()

	// Если в наборе оказался ключ без kid (например, забыли проставить),
	// Find("") всё равно должен вернуть false — не подбирать его «по умолчанию».
	keyNoKid := makePublicJWK(t, keys.AlgECDSAP256, "")

	set := jwk.Set{Keys: []jwk.JWK{keyNoKid}}
	if _, ok := set.Find(""); ok {
		t.Fatal("Find(\"\") не должен возвращать ключи без kid")
	}
}

func TestJWKSet_FindReturnsFirstOnDuplicateKid(t *testing.T) {
	t.Parallel()

	first := makePublicJWK(t, keys.AlgECDSAP256, "rotating")
	second := makePublicJWK(t, keys.AlgECDSAP256, "rotating")

	set := jwk.Set{Keys: []jwk.JWK{first, second}}

	got, ok := set.Find("rotating")
	if !ok {
		t.Fatal("ожидали найти ключ")
	}
	if !reflect.DeepEqual(got, first) {
		t.Fatalf("ожидали первый ключ из набора, получили другой")
	}
}

func TestJWKSet_RotationCoexistence(t *testing.T) {
	t.Parallel()

	// Сценарий ротации: старый и новый ключи одного алгоритма живут в JWKS
	// одновременно. Валидатор должен находить оба, чтобы успеть проверить
	// токены, выпущенные до ротации.
	old := makePublicJWK(t, keys.AlgMLDSA65, "mldsa-2026-04")
	fresh := makePublicJWK(t, keys.AlgMLDSA65, "mldsa-2026-05")

	set := jwk.Set{Keys: []jwk.JWK{old, fresh}}

	if _, ok := set.Find("mldsa-2026-04"); !ok {
		t.Fatal("старый kid не найден — ротация ломается, токены протухнут досрочно")
	}
	if _, ok := set.Find("mldsa-2026-05"); !ok {
		t.Fatal("новый kid не найден — выпускать новые токены нечем")
	}
}

func TestJWKSet_JSONRoundTrip(t *testing.T) {
	t.Parallel()

	want := jwk.Set{
		Keys: []jwk.JWK{
			makePublicJWK(t, keys.AlgECDSAP256, "ec-1"),
			makePublicJWK(t, keys.AlgMLDSA65, "mldsa-1"),
			makePublicJWK(t, keys.AlgHybridECDSAMLDSA65, "hybrid-1"),
		},
	}

	data, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var got jwk.Set
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(got.Keys) != len(want.Keys) {
		t.Fatalf("после round-trip len(Keys) = %d, ожидали %d", len(got.Keys), len(want.Keys))
	}
	for i, k := range want.Keys {
		if got.Keys[i].Kid != k.Kid || got.Keys[i].Kty != k.Kty {
			t.Fatalf("ключ %d: round-trip изменил kid/kty (%q/%q vs %q/%q)",
				i, got.Keys[i].Kid, got.Keys[i].Kty, k.Kid, k.Kty)
		}
	}

	// Конкретные ключи — проверим, что после round-trip их можно собрать
	// обратно через ParsePublic.
	for i, k := range got.Keys {
		if _, err := jwk.ParsePublic(k); err != nil {
			t.Fatalf("ParsePublic[%d] (%s): %v", i, k.Kty, err)
		}
	}
}

func TestJWKSet_EmptySet(t *testing.T) {
	t.Parallel()

	var empty jwk.Set
	if _, ok := empty.Find("any"); ok {
		t.Fatal("Find в пустом наборе не должен находить ничего")
	}

	data, err := json.Marshal(empty)
	if err != nil {
		t.Fatalf("Marshal пустого набора: %v", err)
	}
	// Пустой набор должен сериализоваться как {"keys":[]}, а не {"keys":null}:
	// JWKS-клиенты на некоторых языках не считают null валидным массивом.
	if string(data) != `{"keys":[]}` {
		t.Fatalf("ожидали {\"keys\":[]} для пустого набора, получили %s", data)
	}

	var back jwk.Set
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("Unmarshal пустого набора: %v", err)
	}
}
