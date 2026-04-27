package pqt

import (
	"fmt"
	"time"

	"pqt/token"
)

// Parse разбирает входящий токен на составные части — заголовок, claims,
// байты подписи — но НЕ проверяет саму подпись. Это нужно в двух
// сценариях: (1) посмотреть на содержимое токена при отладке, не
// требуя ключа; (2) дать KeySource возможность взглянуть на header
// (например, на поле Kid — идентификатор ключа), чтобы выбрать,
// какой публичный ключ использовать для проверки.
//
// Кроме разобранных частей возвращается ещё signedMessage — байты,
// над которыми считалась подпись (это просто склейка заголовка и
// payload в исходном виде, до base64). Validate потом передаёт их
// в verifier.Verify; снаружи функции этот результат обычно не нужен.
//
// Срез signature ссылается на тот же массив байт, что и tokenBytes —
// копий не делается ради скорости. Это значит: пока в коде есть
// ссылки на signature, header и claims (например, до конца проверки),
// нельзя менять буфер tokenBytes. Если внешний код перезапишет байты
// этого буфера, проверка подписи увидит уже не те данные, которые
// подписывали.
func Parse(tokenBytes []byte, format token.Format) (
	header token.Header,
	claims token.Claims,
	signature []byte,
	signedMessage []byte,
	err error,
) {
	headerBytes, payloadBytes, sig, err := splitToken(tokenBytes, format)
	if err != nil {
		return token.Header{}, token.Claims{}, nil, nil, err
	}

	h, err := token.DecodeHeader(headerBytes)
	if err != nil {
		return token.Header{}, token.Claims{}, nil, nil, fmt.Errorf("pqt: разбор, заголовок: %w", err)
	}

	c, err := token.DecodePayload(payloadBytes, h.Enc)
	if err != nil {
		return token.Header{}, token.Claims{}, nil, nil, fmt.Errorf("pqt: разбор, payload: %w", err)
	}

	return h, c, sig, joinHeaderPayload(headerBytes, payloadBytes), nil
}

// Validate выполняет полную проверку токена и возвращает claims, если
// всё в порядке.
//
// Что и в каком порядке проверяется:
//
//  1. Опции (KeySource задан, Format известен) — это ошибка вызывающего
//     кода, отдельный класс ErrInvalidOptions.
//  2. Структура токена: разбор формата (text или binary), потом разбор
//     заголовка (JSON) и payload (JSON или CBOR — по полю enc из заголовка).
//  3. Выбор публичного ключа через KeySource, который получает заголовок
//     и должен вернуть подходящий ключ.
//  4. Сверка алгоритма: alg из заголовка должен совпасть с алгоритмом
//     ключа. Эта проверка делается ДО проверки подписи — она и есть
//     защита от подмены alg в заголовке (см. ErrAlgMismatch).
//  5. Проверка подписи: verifier пересчитывает подпись и сравнивает с
//     той, что лежит в токене.
//  6. Проверка claims: срок действия (exp), издатель (iss), получатель
//     (aud), отзыв по jti — если соответствующие опции заданы.
//
// Любой шаг возвращает ошибку с конкретным маркером (ErrSignatureInvalid,
// ErrTokenExpired, ErrIssuerMismatch, ErrAudienceMismatch, ErrAlgMismatch,
// ErrKeyNotFound, ErrInvalidOptions, ErrTokenRevoked) или с маркерами
// разбора формата из пакета token. Текст сообщения содержит подробности
// для логов, но проверять класс ошибки нужно через errors.Is, а не по
// тексту.
//
// Внимание к буферу: tokenBytes внутри Validate не копируется. Срез
// байтов подписи указывает на тот же массив. Если параллельно с
// Validate какой-то код в этой же программе изменит содержимое
// tokenBytes, проверка подписи проверит уже не то, что вошло на вход.
// На практике это редкая ситуация (буфер обычно живёт только в одной
// горутине), но контракт стоит держать в голове.
func Validate(tokenBytes []byte, opts ValidateOptions) (token.Claims, error) {
	if err := opts.validate(); err != nil {
		return token.Claims{}, err
	}

	header, claims, signature, signedMessage, err := Parse(tokenBytes, opts.Format)
	if err != nil {
		return token.Claims{}, err
	}

	verifier, err := opts.KeySource(header)
	if err != nil {
		return token.Claims{}, fmt.Errorf("pqt: подбор ключа: %w", err)
	}
	if verifier == nil {
		return token.Claims{}, ErrKeyNotFound
	}

	// Сверяем алгоритм. Делаем это ДО verifier.Verify сознательно: если
	// бы мы шли сразу в Verify, можно было бы сначала «принять» подпись
	// чужим алгоритмом, а уже потом ловить расхождение. На самом деле
	// верить алгоритму, заявленному в токене, нельзя — он приходит
	// извне и подделывается так же, как и подпись. Источник истины —
	// алгоритм ключа, который вернул KeySource (по kid или статически).
	// Если тот, кто прислал токен, надеялся подменить alg на «слабый»,
	// здесь и упрётся.
	if header.Alg != verifier.Algorithm() {
		return token.Claims{}, fmt.Errorf("%w: header.alg=%s, verifier.alg=%s",
			ErrAlgMismatch, header.Alg, verifier.Algorithm())
	}

	if err := verifier.Verify(signedMessage, signature); err != nil {
		return token.Claims{}, fmt.Errorf("%w: %w", ErrSignatureInvalid, err)
	}

	if err := validateClaims(claims, opts); err != nil {
		return token.Claims{}, err
	}

	return claims, nil
}

// validate проверяет, что в ValidateOptions заполнено всё, без чего
// проверка не имеет смысла. Возвращает ошибку с маркером ErrInvalidOptions —
// чтобы вызывающий код мог отличить «опции собраны неправильно» от
// «токен оказался плохой».
func (o ValidateOptions) validate() error {
	if o.KeySource == nil {
		return fmt.Errorf("%w: не указан KeySource", ErrInvalidOptions)
	}
	if !o.Format.Valid() {
		return fmt.Errorf("%w: неизвестный формат %q", ErrInvalidOptions, o.Format)
	}
	return nil
}

// validateClaims сверяет содержимое токена с ожиданиями вызывающего:
// не истёк ли срок действия, тот ли издатель, тот ли получатель, не
// отозван ли токен. Каждая из проверок может либо отработать, либо
// быть пропущена — это зависит от того, заданы ли соответствующие
// опции.
func validateClaims(c token.Claims, opts ValidateOptions) error {
	clock := opts.Clock
	if clock == nil {
		clock = time.Now
	}
	now := clock()

	// По спецификации PQ-AT exp обязателен. Токен без exp — это «не
	// истечёт никогда», что для access-токена недопустимо: достаточно
	// один раз украсть, и им можно пользоваться годами. Поэтому
	// отсутствие exp (нулевое значение в Go обозначает «поля не было
	// в JSON/CBOR») — это сразу ErrTokenExpired.
	if c.Exp == 0 {
		return fmt.Errorf("%w: exp отсутствует", ErrTokenExpired)
	}
	exp := time.Unix(c.Exp, 0)

	// Если now позже exp — токен истёк. Leeway — допустимая разница
	// часов между сервером-эмитентом и сервером-проверяющим: токен,
	// чей exp на 30 секунд раньше now, при Leeway = 60s ещё пройдёт.
	// Без Leeway (значение по умолчанию) поблажки нет: even one second
	// past exp значит «недействителен».
	if now.Add(-opts.Leeway).After(exp) {
		return fmt.Errorf("%w: exp=%s, now=%s", ErrTokenExpired, exp, now)
	}

	if opts.ExpectedIssuer != "" && c.Iss != opts.ExpectedIssuer {
		return fmt.Errorf("%w: ожидали %q, получили %q",
			ErrIssuerMismatch, opts.ExpectedIssuer, c.Iss)
	}

	if opts.ExpectedAudience != "" && c.Aud != opts.ExpectedAudience {
		return fmt.Errorf("%w: ожидали %q, получили %q",
			ErrAudienceMismatch, opts.ExpectedAudience, c.Aud)
	}

	// Чёрный список jti проверяется в самом конце, потому что:
	// (а) до сюда дошёл уже валидный по подписи и сроку токен — раньше
	// тратить вызов IsRevoked на заведомо плохой токен незачем;
	// (б) если IsRevoked сходит за этой проверкой во внешнее хранилище
	// (Redis, БД), хочется делать это один раз, для уже признанных
	// нормальными токенов.
	if opts.IsRevoked != nil && c.Jti != "" && opts.IsRevoked(c.Jti) {
		return fmt.Errorf("%w: jti=%s", ErrTokenRevoked, c.Jti)
	}

	return nil
}

// splitToken — небольшая обёртка, которая по выбранному формату вызывает
// либо token.ParseText (для текстового JWT-совместимого вида), либо
// token.ParseBinary (для компактного бинарного). Нужна только для того,
// чтобы выше по коду switch по формату оставался в одном месте.
func splitToken(tokenBytes []byte, format token.Format) (header, payload, signature []byte, err error) {
	switch format {
	case token.FormatText:
		return token.ParseText(string(tokenBytes))
	case token.FormatBinary:
		return token.ParseBinary(tokenBytes)
	default:
		return nil, nil, nil, fmt.Errorf("%w: неизвестный формат %q", ErrInvalidOptions, format)
	}
}
