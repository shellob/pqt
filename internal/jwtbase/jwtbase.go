// Package jwtbase — эталонный выпуск и проверка классических JWT через
// golang-jwt/jwt/v5. Используется как точка отсчёта в главе 4.3 диссертации
// для сравнения с PQ-AT по размеру токена и скорости подписи/проверки.
//
// Алгоритм фиксирован: ES256 (ECDSA P-256 + SHA-256, RFC 7515 §3.4). Это
// прямой аналог нашего keys.AlgECDSAP256, поэтому сравнение «JWT vs PQ-AT
// в режиме ecdsa-p256» получается на одном и том же криптопримитиве, и
// разница в размере и скорости отражает накладные расходы формата, а не
// математики.
package jwtbase

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"pqt/token"
)

// Маркерные ошибки. Используются вместе с errors.Is, чтобы вызывающий код
// мог отличать виды отказа без разбора текста сообщений.
var (
	// ErrSignatureInvalid — подпись JWT не прошла проверку.
	ErrSignatureInvalid = errors.New("jwtbase: signature is invalid")

	// ErrTokenExpired — текущее время превышает claim exp с учётом Leeway.
	ErrTokenExpired = errors.New("jwtbase: token expired")

	// ErrIssuerMismatch — claim iss не совпадает с ExpectedIssuer.
	ErrIssuerMismatch = errors.New("jwtbase: issuer mismatch")

	// ErrAudienceMismatch — claim aud не совпадает с ExpectedAudience.
	ErrAudienceMismatch = errors.New("jwtbase: audience mismatch")
)

// jwtClaims — внутреннее представление claims для golang-jwt. Включает все
// поля token.Claims кроме Kind, которое относится к PQ-AT и в чистом JWT
// смысла не имеет.
type jwtClaims struct {
	Scope string `json:"scope,omitempty"`
	jwt.RegisteredClaims
}

// Issue подписывает claims приватным ключом и возвращает компактный JWT-токен
// в формате RFC 7519. Поле Kind игнорируется — оно специфично для PQ-AT.
//
// Если в claims не задан exp, токен будет «вечным» — golang-jwt не отвергает
// такие при выпуске. Семантика «exp обязателен» относится к нашему PQ-AT
// (см. pqt.Validate), а здесь мы намеренно ведём себя как стандартный JWT,
// чтобы сравнение в эксперименте было честным.
func Issue(claims token.Claims, key *ecdsa.PrivateKey) (string, error) {
	if key == nil {
		return "", errors.New("jwtbase: nil private key")
	}

	registered := jwt.RegisteredClaims{
		Subject: claims.Sub,
		Issuer:  claims.Iss,
		ID:      claims.Jti,
	}
	if claims.Aud != "" {
		registered.Audience = jwt.ClaimStrings{claims.Aud}
	}
	if claims.Exp != 0 {
		registered.ExpiresAt = jwt.NewNumericDate(time.Unix(claims.Exp, 0))
	}
	if claims.Iat != 0 {
		registered.IssuedAt = jwt.NewNumericDate(time.Unix(claims.Iat, 0))
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwtClaims{
		Scope:            claims.Scope,
		RegisteredClaims: registered,
	})
	signed, err := tok.SignedString(key)
	if err != nil {
		return "", fmt.Errorf("jwtbase: подпись JWT: %w", err)
	}
	return signed, nil
}

// ValidateOptions — параметры проверки JWT. Семантически совпадают с
// pqt.ValidateOptions, чтобы вызывающий код в эксперименте мог использовать
// общий тип.
type ValidateOptions struct {
	// ExpectedIssuer — если задан, проверяется совпадение с claim iss.
	ExpectedIssuer string

	// ExpectedAudience — если задан, проверяется наличие в claim aud.
	ExpectedAudience string

	// Clock — источник «текущего времени» для проверки exp. Если nil, time.Now.
	Clock func() time.Time

	// Leeway — допустимая разница часов с issuer'ом. По умолчанию 0.
	Leeway time.Duration
}

// Validate проверяет подпись и стандартные claims JWT. Возвращает claims в
// формате token.Claims (без поля Kind, которое в JWT не было).
func Validate(tokenStr string, key *ecdsa.PublicKey, opts ValidateOptions) (token.Claims, error) {
	if key == nil {
		return token.Claims{}, errors.New("jwtbase: nil public key")
	}

	clock := opts.Clock
	if clock == nil {
		clock = time.Now
	}

	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"ES256"}),
		jwt.WithLeeway(opts.Leeway),
		jwt.WithTimeFunc(clock),
	)

	parsed, err := parser.ParseWithClaims(tokenStr, &jwtClaims{}, func(_ *jwt.Token) (any, error) {
		return key, nil
	})
	if err != nil {
		return token.Claims{}, classifyValidationError(err)
	}

	c, ok := parsed.Claims.(*jwtClaims)
	if !ok {
		return token.Claims{}, errors.New("jwtbase: claims неожиданного типа")
	}

	out := token.Claims{
		Sub:   c.Subject,
		Iss:   c.Issuer,
		Jti:   c.ID,
		Scope: c.Scope,
	}
	if len(c.Audience) > 0 {
		// В token.Claims одно поле Aud; берём первый элемент. Проверка
		// ExpectedAudience ниже идёт по полному массиву через slices.Contains —
		// поэтому это упрощение «потеря не первого aud в out» не приводит
		// к ложному mismatch.
		out.Aud = c.Audience[0]
	}
	if c.ExpiresAt != nil {
		out.Exp = c.ExpiresAt.Unix()
	}
	if c.IssuedAt != nil {
		out.Iat = c.IssuedAt.Unix()
	}

	if opts.ExpectedIssuer != "" && out.Iss != opts.ExpectedIssuer {
		return token.Claims{}, fmt.Errorf("%w: ожидали %q, получили %q",
			ErrIssuerMismatch, opts.ExpectedIssuer, out.Iss)
	}
	if opts.ExpectedAudience != "" && !slices.Contains(c.Audience, opts.ExpectedAudience) {
		return token.Claims{}, fmt.Errorf("%w: ожидали %q в %v",
			ErrAudienceMismatch, opts.ExpectedAudience, c.Audience)
	}

	return out, nil
}

// classifyValidationError превращает ошибки golang-jwt в наши маркерные
// ErrSignatureInvalid / ErrTokenExpired. Ошибки структурного парсинга
// возвращаются как есть с префиксом «jwtbase:».
func classifyValidationError(err error) error {
	switch {
	case errors.Is(err, jwt.ErrTokenExpired):
		return fmt.Errorf("%w: %w", ErrTokenExpired, err)
	case errors.Is(err, jwt.ErrTokenSignatureInvalid):
		// ErrTokenUnverifiable намеренно не маппится сюда: библиотека
		// возвращает его, когда keyFunc вернул ошибку или ключ не подходит
		// по типу. Это не «подпись плохая», а «не смогли начать проверку» —
		// падает в default-ветку с более точным сообщением.
		return fmt.Errorf("%w: %w", ErrSignatureInvalid, err)
	default:
		return fmt.Errorf("jwtbase: разбор JWT: %w", err)
	}
}
