package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"pqt/jwk"
	"pqt/keys"
)

const keygenUsage = `pqt-cli keygen — сгенерировать пару ключей в JWK-формате.

Использование:
  pqt-cli keygen --alg <алгоритм> --kid <идентификатор> --out <директория>

Опции:
  --alg   Алгоритм ключа. Допустимо:
            ecdsa-p256
            mldsa44 | mldsa65 | mldsa87
            hybrid-ecdsa-mldsa44 | hybrid-ecdsa-mldsa65 | hybrid-ecdsa-mldsa87
  --kid   Идентификатор ключа. Используется как имя файла и попадает в JWK.kid.
  --out   Директория, в которую положить два файла:
            <kid>.priv.jwk.json — приватный ключ;
            <kid>.pub.jwk.json  — публичный ключ.
          Если директории нет, она будет создана.
`

func runKeygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, keygenUsage) }

	alg := fs.String("alg", "", "алгоритм ключа")
	kid := fs.String("kid", "", "идентификатор ключа")
	outDir := fs.String("out", "", "директория для записи JWK-файлов")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if *alg == "" || *kid == "" || *outDir == "" {
		fs.Usage()
		return fmt.Errorf("укажите --alg, --kid и --out")
	}

	priv, err := generatePrivateKey(keys.Alg(*alg))
	if err != nil {
		return err
	}

	privJWK, err := jwk.MarshalPrivate(priv)
	if err != nil {
		return fmt.Errorf("сериализация приватного ключа: %w", err)
	}
	pubJWK, err := jwk.MarshalPublic(priv.Public())
	if err != nil {
		return fmt.Errorf("сериализация публичного ключа: %w", err)
	}
	privJWK.Kid = *kid
	pubJWK.Kid = *kid

	// Права 0o700 на директории ключей: читать, писать и заходить может
	// только владелец, остальные пользователи операционной системы — нет.
	// Пишем приватные ключи; если бы стояло 0o755, любой залогиненный
	// пользователь смог бы их прочитать. Сами файлы внутри тоже пишутся
	// с ограниченными правами — см. writeJWK в io.go.
	if err := os.MkdirAll(*outDir, 0o700); err != nil {
		return fmt.Errorf("создание директории %q: %w", *outDir, err)
	}

	privPath := filepath.Join(*outDir, *kid+".priv.jwk.json")
	pubPath := filepath.Join(*outDir, *kid+".pub.jwk.json")

	if err := writeJWK(privPath, privJWK); err != nil {
		return err
	}
	if err := writeJWK(pubPath, pubJWK); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "сгенерирован ключ %s (kid=%s)\n  приватный: %s\n  публичный: %s\n",
		*alg, *kid, privPath, pubPath)
	return nil
}

// generatePrivateKey создаёт свежий приватный ключ нужного алгоритма.
// Для гибридов классическая половинка фиксирована (ECDSA P-256), а
// постквантовая половинка определяется уровнем ML-DSA, переданным
// через alg: 44, 65 или 87. Чем выше уровень — тем длиннее подпись и
// крепче гарантии (см. keys/mldsa.go).
func generatePrivateKey(alg keys.Alg) (keys.PrivateKey, error) {
	switch alg {
	case keys.AlgECDSAP256:
		k, err := keys.GenerateECDSA()
		if err != nil {
			return nil, fmt.Errorf("генерация ECDSA: %w", err)
		}
		return k, nil
	case keys.AlgMLDSA44, keys.AlgMLDSA65, keys.AlgMLDSA87:
		k, err := keys.GenerateMLDSA(alg)
		if err != nil {
			return nil, fmt.Errorf("генерация %s: %w", alg, err)
		}
		return k, nil
	case keys.AlgHybridECDSAMLDSA44:
		return generateHybrid(keys.AlgMLDSA44)
	case keys.AlgHybridECDSAMLDSA65:
		return generateHybrid(keys.AlgMLDSA65)
	case keys.AlgHybridECDSAMLDSA87:
		return generateHybrid(keys.AlgMLDSA87)
	default:
		return nil, fmt.Errorf("неизвестный алгоритм %q", alg)
	}
}

func generateHybrid(pqAlg keys.Alg) (keys.PrivateKey, error) {
	k, err := keys.GenerateHybrid(pqAlg)
	if err != nil {
		return nil, fmt.Errorf("генерация гибрида с %s: %w", pqAlg, err)
	}
	return k, nil
}
