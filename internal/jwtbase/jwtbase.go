// Package jwtbase — эталонная реализация выпуска и проверки классического
// JWT поверх популярной библиотеки golang-jwt/jwt/v5. Это «контроль» для
// эксперимента из главы 4.3 диссертации: чтобы корректно сравнивать
// PQ-AT (наш формат) с JWT по размеру токена и скорости работы, нужен
// именно стандартный JWT, а не какая-то его вольная интерпретация.
//
// Алгоритм фиксирован — ES256 (ECDSA на кривой P-256 с хешем SHA-256,
// RFC 7515 §3.4). Это тот же самый криптопримитив, что у нашего
// keys.AlgECDSAP256, поэтому сравнение «JWT vs PQ-AT в режиме ECDSA P-256»
// делается на одной математике, и разница в цифрах честно отражает
// накладные расходы формата (Base64url, JSON-заголовок, точки-разделители),
// а не разницу в стоимости подписи.
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

// Маркерные ошибки. Это значения, которые сравниваются через errors.Is —
// удобный способ отличать причины отказа в логике вызывающего кода, не
// разбирая текст сообщения. Тексты могут уточняться, идентичность ошибки
// определяется именно по этим переменным.
var (
	// ErrSignatureInvalid — криптографическая подпись JWT не сошлась с
	// публичным ключом. Это либо токен подписан другим ключом, либо его
	// после выпуска кто-то изменил.
	ErrSignatureInvalid = errors.New("jwtbase: signature is invalid")

	// ErrTokenExpired — на момент проверки текущее время уже больше,
	// чем claim exp плюс допуск на расхождение часов (Leeway).
	ErrTokenExpired = errors.New("jwtbase: token expired")

	// ErrIssuerMismatch — claim iss из токена не совпадает с ExpectedIssuer
	// из опций. Сервер требует токены конкретного издателя, а пришёл от
	// чужого.
	ErrIssuerMismatch = errors.New("jwtbase: issuer mismatch")

	// ErrAudienceMismatch — ExpectedAudience из опций не нашлось в claim aud
	// токена. Токен подписан легально, но был выпущен для другого сервиса.
	ErrAudienceMismatch = errors.New("jwtbase: audience mismatch")
)

// jwtClaims — формат claims, в котором golang-jwt сериализует payload.
// Встраивает jwt.RegisteredClaims (стандартные RFC 7519 поля sub, iss,
// aud, exp, iat, jti) и добавляет своё нестандартное поле scope. Поле Kind
// из нашего token.Claims намеренно опущено: оно нужно только в PQ-AT
// (чтобы отличать access-токен от refresh при отзыве), а в обычном JWT
// его не бывает — это упростило бы PQ-AT-фичу мимо честного сравнения.
type jwtClaims struct {
	Scope string `json:"scope,omitempty"`
	jwt.RegisteredClaims
}

// Issue подписывает claims приватным ключом ECDSA P-256 и возвращает готовую
// строку JWT в компактном формате RFC 7519 (header.payload.signature, всё
// в base64url через точки). Поле claims.Kind игнорируется — оно есть только
// в PQ-AT и в чистом JWT не передаётся.
//
// Если claims.Exp равен нулю, токен будет выпущен без exp и формально
// получится «вечным» — библиотека golang-jwt не считает это ошибкой при
// выпуске. В нашем PQ-AT pqt.Validate такой токен бы отверг (см.
// pqt.ErrMissingExpiry), но здесь мы сознательно ведём себя как
// «честный» стандартный JWT: если бы мы вшили требование exp в эталон,
// сравнение в главе 4.3 получилось бы нечестным — мы бы сравнивали свои
// правила с собой.
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

// ValidateOptions — параметры проверки JWT. Поля сделаны точно такими же
// по смыслу, что и в pqt.ValidateOptions: эксперимент в главе 4.3 гоняет
// одни и те же бенчмарки на двух реализациях, и совпадение опций позволяет
// обойтись без отдельных конфигов на каждую.
type ValidateOptions struct {
	// ExpectedIssuer — если задан, проверяется, что claim iss токена в
	// точности равен этому значению. Иначе возвращается ErrIssuerMismatch.
	ExpectedIssuer string

	// ExpectedAudience — если задан, проверяется, что эта строка
	// присутствует в claim aud. JWT допускает aud как массив, поэтому
	// проверяем именно вхождение в список (через slices.Contains), а не
	// равенство.
	ExpectedAudience string

	// Clock — источник «текущего времени», от которого библиотека
	// отсчитывает exp. В тестах подменяется фиксированным временем,
	// чтобы детерминированно проверять поведение около границ exp.
	// Если nil — берётся time.Now.
	Clock func() time.Time

	// Leeway — допустимая разница часов между сервером и валидатором.
	// Прибавляется к exp при проверке. По умолчанию 0 — никакой
	// поблажки нет.
	Leeway time.Duration
}

// Validate проверяет подпись и стандартные claims JWT и возвращает их
// в нашем формате token.Claims (поле Kind остаётся пустым — в исходном
// JWT его нет).
//
// Жёстко прописан список разрешённых алгоритмов — только ES256.
// jwt.WithValidMethods закрывает классическую дыру JWT с подменой alg:
// без этого ограничения злоумышленник мог бы взять валидный ES256-токен,
// поменять заголовок на alg=none или alg=HS256 и заставить нас принять
// его без подписи или проверить подпись симметричным ключом, который
// он сам и подобрал из публичного ключа.
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
		// В нашем token.Claims поле Aud — одна строка, тогда как в JWT
		// audience может быть массивом. Здесь берём первый элемент только
		// для возврата клиенту (чтобы было что показать). Сама проверка
		// ExpectedAudience ниже идёт по полному массиву через
		// slices.Contains — поэтому такое упрощение не приведёт к ложному
		// rejection, если нужное audience стоит не первым.
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

// classifyValidationError превращает внутренние ошибки golang-jwt в наши
// маркерные ErrSignatureInvalid / ErrTokenExpired, чтобы вызывающий код
// мог различать их через errors.Is. Ошибки структурного разбора (битый
// base64, сломанный JSON в payload и т. д.) возвращаются с префиксом
// «jwtbase:» — для них отдельной маркерной ошибки не делаем, потому что
// в эксперименте они в принципе не должны возникать.
func classifyValidationError(err error) error {
	switch {
	case errors.Is(err, jwt.ErrTokenExpired):
		return fmt.Errorf("%w: %w", ErrTokenExpired, err)
	case errors.Is(err, jwt.ErrTokenSignatureInvalid):
		// jwt.ErrTokenUnverifiable сюда намеренно не маппится: библиотека
		// возвращает её, когда keyFunc сама вернула ошибку или ключ
		// неподходящего типа. Это не «подпись плохая», а «не смогли
		// начать проверку вообще» — пусть падает в default-ветку с
		// более точным сообщением.
		return fmt.Errorf("%w: %w", ErrSignatureInvalid, err)
	default:
		return fmt.Errorf("jwtbase: разбор JWT: %w", err)
	}
}
