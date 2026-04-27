package keys

import (
	"encoding"
	"fmt"

	"github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/schemes"
)

// MLDSAPrivateKey — приватный ключ ML-DSA (Module-Lattice-Based Digital
// Signature Algorithm), постквантовой подписи по стандарту FIPS 204.
//
// Сами математические операции (генерация, подпись, проверка) делает
// библиотека cloudflare/circl — мы её только оборачиваем, чтобы наружу
// был тот же интерфейс PrivateKey, что и у ECDSA. У circl своё
// представление приватного ключа (sign.PrivateKey), здесь оно лежит в
// поле sk; уровень безопасности (44, 65 или 87 — см. alg.go) хранится
// в поле alg, чтобы не вытаскивать его из scheme каждый раз.
//
// Размеры ключей и подписей — фиксированные для каждого уровня:
//
//	mldsa44: подпись 2420 байт, открытый ключ 1312, приватный 2560.
//	mldsa65: подпись 3309, открытый ключ 1952, приватный 4032.
//	mldsa87: подпись 4627, открытый ключ 2592, приватный 4896.
//
// В отличие от ECDSA, где все эти величины измеряются десятками байт,
// ML-DSA «дорогой» по размеру — главная плата за постквантовую стойкость.
type MLDSAPrivateKey struct {
	scheme sign.Scheme
	sk     sign.PrivateKey
	alg    Alg
}

// MLDSAPublicKey — парный публичный ключ ML-DSA.
type MLDSAPublicKey struct {
	scheme sign.Scheme
	pk     sign.PublicKey
	alg    Alg
}

// GenerateMLDSA создаёт новую пару ключей ML-DSA нужного уровня. Источник
// случайности — внутри circl, по умолчанию crypto/rand.
//
// Допустимые значения параметра alg: AlgMLDSA44, AlgMLDSA65 или AlgMLDSA87.
// Любое другое — это ErrUnsupportedAlg.
func GenerateMLDSA(alg Alg) (*MLDSAPrivateKey, error) {
	scheme, err := mldsaScheme(alg)
	if err != nil {
		return nil, err
	}
	_, sk, err := scheme.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("keys: mldsa generate: %w", err)
	}
	return &MLDSAPrivateKey{scheme: scheme, sk: sk, alg: alg}, nil
}

// Sign возвращает ML-DSA-подпись над сообщением. Размер подписи —
// фиксированный для уровня (см. описание у MLDSAPrivateKey).
//
// Третий аргумент scheme.Sign — это контекст (ML-DSA умеет привязывать
// подпись к произвольной строке-метке) и pre-hashed-режим (когда подписывают
// заранее посчитанный хеш, не само сообщение). В спецификации PQ-AT
// обе эти возможности не используются, поэтому передаём nil.
func (p *MLDSAPrivateKey) Sign(message []byte) ([]byte, error) {
	return p.scheme.Sign(p.sk, message, nil), nil
}

// Public возвращает парный публичный ключ. У circl публичная часть
// получается из приватной через метод sk.Public(); никаких тяжёлых
// вычислений не делается, и секретный материал в публичный не утекает.
func (p *MLDSAPrivateKey) Public() PublicKey {
	return &MLDSAPublicKey{
		scheme: p.scheme,
		pk:     p.sk.Public().(sign.PublicKey),
		alg:    p.alg,
	}
}

// Algorithm возвращает уровень ML-DSA, который был выбран при генерации
// или загрузке этого ключа.
func (p *MLDSAPrivateKey) Algorithm() Alg { return p.alg }

// PrivateBytes возвращает приватный ключ в байтовом виде, как его
// сериализует circl. Длина зависит от уровня и совпадает с тем, что
// прописано в FIPS 204 (см. таблицу размеров в описании MLDSAPrivateKey).
//
// Используется при сохранении ключа в JWK (поле priv).
func (p *MLDSAPrivateKey) PrivateBytes() ([]byte, error) {
	return marshalCirclBinary(p.sk)
}

// PublicBytes возвращает публичную часть в байтовом виде circl.
// Используется при сохранении в JWK (поле pub).
func (p *MLDSAPrivateKey) PublicBytes() ([]byte, error) {
	return marshalCirclBinary(p.sk.Public())
}

// Verify проверяет ML-DSA-подпись. Третий и четвёртый аргументы у
// scheme.Verify — те же, что у Sign (контекст и pre-hashed-режим);
// в PQ-AT не используются, передаём nil.
//
// Возвращает ErrInvalidSignature если подпись не сошлась — без подробностей,
// чтобы не давать атакующему обратной связи о том, что именно не так.
func (v *MLDSAPublicKey) Verify(message, signature []byte) error {
	if !v.scheme.Verify(v.pk, message, signature, nil) {
		return ErrInvalidSignature
	}
	return nil
}

// Algorithm возвращает уровень ML-DSA этого публичного ключа.
func (v *MLDSAPublicKey) Algorithm() Alg { return v.alg }

// Bytes возвращает публичный ключ в байтовом виде circl. Используется
// при сохранении в JWK (поле pub).
func (v *MLDSAPublicKey) Bytes() ([]byte, error) {
	return marshalCirclBinary(v.pk)
}

// NewMLDSAPrivateFromBytes собирает приватный ML-DSA-ключ нужного уровня
// из байтов, ранее полученных через PrivateBytes (или из любого другого
// совместимого с circl источника). Если байты битые или их длина не
// соответствует уровню — circl вернёт ошибку, а мы обернём её в
// ErrInvalidKey.
func NewMLDSAPrivateFromBytes(alg Alg, data []byte) (*MLDSAPrivateKey, error) {
	scheme, err := mldsaScheme(alg)
	if err != nil {
		return nil, err
	}
	sk, err := scheme.UnmarshalBinaryPrivateKey(data)
	if err != nil {
		return nil, fmt.Errorf("%w: разбор приватного ML-DSA-ключа: %w", ErrInvalidKey, err)
	}
	return &MLDSAPrivateKey{scheme: scheme, sk: sk, alg: alg}, nil
}

// NewMLDSAPublicFromBytes — то же самое, но для публичного ключа.
// Используется при загрузке из JWK (поле pub).
func NewMLDSAPublicFromBytes(alg Alg, data []byte) (*MLDSAPublicKey, error) {
	scheme, err := mldsaScheme(alg)
	if err != nil {
		return nil, err
	}
	pk, err := scheme.UnmarshalBinaryPublicKey(data)
	if err != nil {
		return nil, fmt.Errorf("%w: разбор публичного ML-DSA-ключа: %w", ErrInvalidKey, err)
	}
	return &MLDSAPublicKey{scheme: scheme, pk: pk, alg: alg}, nil
}

// mldsaScheme переводит наш Alg в объект-схему из circl. Внутри circl
// схемы зарегистрированы по строковым именам в стиле «ML-DSA-44», и
// получить нужную можно через schemes.ByName(). Если бы какая-то из
// этих имён не оказалась в реестре (битая сборка circl, неправильная
// версия) — это уже ошибка библиотеки, поэтому возвращаем
// ErrUnsupportedAlg даже в таком случае: внешний код всё равно ничего
// сделать не может.
func mldsaScheme(alg Alg) (sign.Scheme, error) {
	var name string
	switch alg {
	case AlgMLDSA44:
		name = "ML-DSA-44"
	case AlgMLDSA65:
		name = "ML-DSA-65"
	case AlgMLDSA87:
		name = "ML-DSA-87"
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedAlg, alg)
	}
	scheme := schemes.ByName(name)
	if scheme == nil {
		return nil, fmt.Errorf("%w: схема %q не найдена в реестре circl",
			ErrUnsupportedAlg, name)
	}
	return scheme, nil
}

// marshalCirclBinary — общий код, который сериализует приватный или
// публичный ключ circl в байты. По контракту библиотеки оба интерфейса
// (sign.PrivateKey и sign.PublicKey) обязаны реализовывать стандартный
// encoding.BinaryMarshaler. На случай, если это однажды перестанет быть
// правдой (например, при обновлении circl), здесь стоит явная проверка
// type assertion с возвратом ErrInvalidKey — лучше явная ошибка, чем
// паника.
func marshalCirclBinary(key any) ([]byte, error) {
	m, ok := key.(encoding.BinaryMarshaler)
	if !ok {
		return nil, fmt.Errorf("%w: ключ %T не реализует BinaryMarshaler",
			ErrInvalidKey, key)
	}
	b, err := m.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("%w: сериализация ключа: %w", ErrInvalidKey, err)
	}
	return b, nil
}

// Эти две строчки — статическая проверка во время компиляции, что
// интерфейсы circl действительно поддерживают BinaryMarshaler. Если
// при будущем обновлении circl авторы изменят контракт и эти interface
// перестанут им удовлетворять — Go откажется собирать пакет, и проблему
// будет видно сразу, а не в рантайме где-нибудь у пользователя.
var (
	_ encoding.BinaryMarshaler = (sign.PublicKey)(nil)
	_ encoding.BinaryMarshaler = (sign.PrivateKey)(nil)
)
