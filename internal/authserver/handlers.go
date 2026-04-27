package authserver

import (
	"errors"
	"net/http"
	"time"

	"pqt"
	"pqt/keys"
	"pqt/token"
)

// maxTokenRequestBody — потолок размера тела запроса на эндпоинты /auth/*.
// Реальная полезная нагрузка — это grant_type, username/password или
// refresh_token, или отзываемый токен; всё это укладывается в килобайты.
// Лимит 64 КБ берётся с большим запасом и при этом не даёт злоумышленнику
// прислать гигантский POST и съесть память сервера.
const maxTokenRequestBody = 64 * 1024

// tokenResponse — успешный ответ эндпоинтов /auth/token и /auth/refresh
// (RFC 6749 §5.1). Тег `omitempty` в JSON означает «не выводить поле, если
// оно пустое»: если refresh-токен не выпускался, в ответе просто не будет
// полей refresh_token и refresh_expires_in.
type tokenResponse struct {
	AccessToken      string `json:"access_token"`
	TokenType        string `json:"token_type"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshToken     string `json:"refresh_token,omitempty"`
	RefreshExpiresIn int    `json:"refresh_expires_in,omitempty"`
	Scope            string `json:"scope,omitempty"`
}

// handleToken — POST /auth/token, выпуск пары токенов по логину и паролю.
//
// Поддерживается только один режим — grant_type=password (RFC 6749 §4.3,
// Resource Owner Password Credentials): клиент присылает логин и пароль
// в теле запроса, сервер их проверяет и сразу возвращает access- и
// refresh-токены. Никаких редиректов и промежуточных authorization code,
// в отличие от authorization code flow.
//
// В реальном OAuth-сервере password grant давно считается устаревшим —
// клиент видит чужой пароль, и нет защиты от фишинга через подменённую
// форму логина. Для эксперимента из главы 4 диссертации это значения не
// имеет: нас интересуют скорость и размер токенов PQ-AT, а не фронт.
func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxTokenRequestBody)
	if err := r.ParseForm(); err != nil {
		s.writeOAuthError(w, http.StatusBadRequest, "invalid_request",
			"не удалось разобрать тело запроса")
		return
	}

	if r.PostForm.Get("grant_type") != "password" {
		s.writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type",
			"поддерживается только grant_type=password")
		return
	}

	username := r.PostForm.Get("username")
	password := r.PostForm.Get("password")
	if username == "" || password == "" {
		s.writeOAuthError(w, http.StatusBadRequest, "invalid_request",
			"требуются параметры username и password")
		return
	}

	user, ok := s.users.Authenticate(username, password)
	if !ok {
		s.writeOAuthError(w, http.StatusUnauthorized, "invalid_grant",
			"неверный логин или пароль")
		return
	}

	scope := limitScope(r.PostForm.Get("scope"), user.Scope)

	resp, err := s.issuePair(user.Username, scope)
	if err != nil {
		s.cfg.Logger.Error("authserver: выпуск пары токенов", "err", err)
		s.writeOAuthError(w, http.StatusInternalServerError, "server_error",
			"не удалось выпустить токен")
		return
	}

	s.writeJSON(w, http.StatusOK, resp)
}

// handleRefresh — POST /auth/refresh.
//
// Принимает grant_type=refresh_token + сам refresh_token. При успехе помечает
// старый refresh использованным и выдаёт новую пару (access + новый refresh) —
// это и есть ротация.
//
// Если refresh уже использовали ранее, его нет в хранилище, он отозван или
// подпись не сходится — отвечаем единственным кодом invalid_grant без
// подробностей. Это сделано специально: иначе атакующий по разным ответам
// сервера различал бы сценарии и понимал, есть ли такой токен в системе.
func (s *Server) handleRefresh(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxTokenRequestBody)
	if err := r.ParseForm(); err != nil {
		s.writeOAuthError(w, http.StatusBadRequest, "invalid_request",
			"не удалось разобрать тело запроса")
		return
	}

	if r.PostForm.Get("grant_type") != "refresh_token" {
		s.writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type",
			"поддерживается только grant_type=refresh_token")
		return
	}

	refreshToken := r.PostForm.Get("refresh_token")
	if refreshToken == "" {
		s.writeOAuthError(w, http.StatusBadRequest, "invalid_request",
			"требуется параметр refresh_token")
		return
	}

	claims, err := s.validateOwnRefresh(refreshToken)
	if err != nil {
		s.cfg.Logger.Info("authserver: refresh-токен отвергнут", "reason", err.Error())
		s.writeOAuthError(w, http.StatusUnauthorized, "invalid_grant",
			"refresh-токен невалиден")
		return
	}

	// Достаём сессию refresh-токена и помечаем её использованной. MarkUsed
	// вернёт false в двух случаях: сессии нет (например, сервер
	// перезапускали и in-memory хранилище потерялось) или её уже один раз
	// использовали. Второе — признак того, что кто-то повторно прислал
	// один и тот же refresh-токен. На практике это либо легальный
	// клиент повторил запрос после сетевого сбоя, не заметив, что
	// первый прошёл, либо токен был украден и злоумышленник пытается
	// им воспользоваться. Различить эти два случая сервер не может, и
	// безопасный ответ один — отказать.
	if !s.refresh.MarkUsed(claims.Jti) {
		s.cfg.Logger.Warn("authserver: повторное использование refresh-токена",
			"jti", claims.Jti, "sub", claims.Sub)
		s.writeOAuthError(w, http.StatusUnauthorized, "invalid_grant",
			"refresh-токен уже использован")
		return
	}

	resp, err := s.issuePair(claims.Sub, claims.Scope)
	if err != nil {
		s.cfg.Logger.Error("authserver: выпуск пары при refresh", "err", err)
		s.writeOAuthError(w, http.StatusInternalServerError, "server_error",
			"не удалось выпустить токен")
		return
	}

	s.writeJSON(w, http.StatusOK, resp)
}

// handleRevoke — POST /auth/revoke (RFC 7009).
//
// Принимает обязательный параметр token и необязательный token_type_hint.
// По §2.2 RFC мы возвращаем 200 даже если токена не нашли или формат не
// разобрался — это специально, чтобы по ответу сервера нельзя было понять,
// есть ли вообще такой токен в системе.
func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxTokenRequestBody)
	if err := r.ParseForm(); err != nil {
		// Тело запроса пришло в нечитаемом виде. По RFC 6749 это
		// invalid_request — структурная ошибка запроса, не отзыва.
		s.writeOAuthError(w, http.StatusBadRequest, "invalid_request",
			"не удалось разобрать тело запроса")
		return
	}

	tokenValue := r.PostForm.Get("token")
	hint := r.PostForm.Get("token_type_hint")
	if tokenValue == "" {
		// Параметр token обязательный (RFC 7009 §2.1).
		s.writeOAuthError(w, http.StatusBadRequest, "invalid_request",
			"требуется параметр token")
		return
	}

	// Сначала разбираем токен и пытаемся понять его тип. Если разбор не
	// удался — по RFC всё равно отвечаем 200, ничего не трогая в хранилищах.
	header, claims, _, _, err := pqt.Parse([]byte(tokenValue), token.FormatText)
	if err == nil {
		s.applyRevocation(header, claims, hint)
	}

	w.WriteHeader(http.StatusOK)
}

// applyRevocation проводит сам отзыв: либо удаляет refresh-сессию из
// хранилища, либо добавляет jti access-токена в чёрный список. Решение
// принимается по полю Kind в claims: оно подписано вместе с остальным
// токеном, и подменить его снаружи нельзя.
//
// Подсказка token_type_hint из тела запроса используется только в одном
// узком сценарии: токен выпущен старой версией сервера, в которой поля
// Kind ещё не было. Если Kind есть — hint игнорируется, и вот почему:
// иначе злоумышленник мог бы подсунуть свой access-токен и hint=refresh_token,
// сервер пошёл бы удалять refresh-сессию (которой под таким jti нет),
// а сам access так бы и остался валидным до своего естественного истечения.
func (s *Server) applyRevocation(_ token.Header, c token.Claims, hint string) {
	if c.Jti == "" {
		return
	}
	kind := c.Kind
	if kind == "" {
		kind = hint
	}
	if kind == token.KindRefresh || kind == "refresh_token" {
		s.refresh.Delete(c.Jti)
		return
	}
	// Сюда попадаем для access-токена и для токена с пустым Kind без
	// полезной подсказки — кладём в чёрный список access-токенов.
	s.revoked.Revoke(c.Jti, s.cfg.Now())
}

// issuePair выпускает пару (access, refresh) для пользователя с заданным
// набором scope. Используется и при первичном логине (handleToken), и при
// ротации refresh-токена (handleRefresh).
func (s *Server) issuePair(username, scope string) (tokenResponse, error) {
	keyEntry := s.keys.Default()
	now := s.cfg.Now()

	access, err := s.issueOne(keyEntry, username, scope, token.KindAccess, s.cfg.AccessTTL, now)
	if err != nil {
		return tokenResponse{}, err
	}

	refresh, err := s.issueOne(keyEntry, username, scope, token.KindRefresh, s.cfg.RefreshTTL, now)
	if err != nil {
		return tokenResponse{}, err
	}

	// Запоминаем сессию refresh-токена — потом по ней будем искать
	// в /auth/refresh при попытке обновления.
	s.refresh.Save(RefreshSession{
		JTI:       refresh.jti,
		Username:  username,
		Scope:     scope,
		IssuedAt:  now,
		ExpiresAt: now.Add(s.cfg.RefreshTTL),
	})

	return tokenResponse{
		AccessToken:      string(access.bytes),
		TokenType:        "Bearer",
		ExpiresIn:        int(s.cfg.AccessTTL.Seconds()),
		RefreshToken:     string(refresh.bytes),
		RefreshExpiresIn: int(s.cfg.RefreshTTL.Seconds()),
		Scope:            scope,
	}, nil
}

// issuedToken — то, что возвращает issueOne: сами байты токена и его jti.
// Хранится отдельно, чтобы не разбирать токен ещё раз только ради jti.
type issuedToken struct {
	bytes []byte
	jti   string
}

func (s *Server) issueOne(
	key *KeyEntry,
	username, scope, kind string,
	ttl time.Duration,
	now time.Time,
) (issuedToken, error) {
	jti, err := newJTI()
	if err != nil {
		return issuedToken{}, err
	}
	claims := token.Claims{
		Sub: username,
		Iss: s.cfg.Issuer,
		// aud (audience) — кому токен предназначен. В реальной системе сюда
		// прописывается идентификатор клиентского сервиса (например
		// "https://api.example.com"), и валидатор отвергает токены, выписанные
		// для других сервисов. У нас прототип, клиентский сервис один — поэтому
		// просто берём имя издателя.
		Aud:   s.cfg.Issuer,
		Iat:   now.Unix(),
		Exp:   now.Add(ttl).Unix(),
		Jti:   jti,
		Scope: scope,
		Kind:  kind,
	}
	tokenBytes, err := pqt.Issue(claims, pqt.IssueOptions{
		Signer: key.Private,
		Codec:  token.CodecJSON,
		Format: token.FormatText,
		Kid:    key.Kid,
	})
	if err != nil {
		return issuedToken{}, err
	}
	return issuedToken{bytes: tokenBytes, jti: jti}, nil
}

// validateOwnRefresh проверяет, что присланный refresh-токен подписан
// текущим сервером, не истёк, не отозван и имеет kind="refresh". Возвращает
// разобранные claims при успехе.
func (s *Server) validateOwnRefresh(refreshToken string) (token.Claims, error) {
	claims, err := pqt.Validate([]byte(refreshToken), pqt.ValidateOptions{
		KeySource: func(h token.Header) (keys.PublicKey, error) {
			entry, ok := s.keys.ByKid(h.Kid)
			if !ok {
				return nil, pqt.ErrKeyNotFound
			}
			return entry.Public, nil
		},
		Format:           token.FormatText,
		ExpectedIssuer:   s.cfg.Issuer,
		ExpectedAudience: s.cfg.Issuer,
		Clock:            s.cfg.Now,
		IsRevoked:        s.revoked.IsRevoked,
	})
	if err != nil {
		return token.Claims{}, err
	}
	if claims.Kind != token.KindRefresh {
		return token.Claims{}, errors.New("в токене kind не равен refresh")
	}
	return claims, nil
}

// handleJWKS — GET /.well-known/pq-jwks, набор публичных ключей сервера.
//
// Любой ресурс-сервер, который проверяет наши токены, должен где-то взять
// публичную часть ключа подписи. Стандартный путь — забрать её отсюда в
// формате JSON Web Key Set (RFC 7517): сервер выкладывает все свои публичные
// ключи на постоянный URL, валидатор их скачивает и кеширует у себя, а потом
// по полю kid из заголовка токена находит нужный.
//
// Заголовок Cache-Control с max-age=300 (5 минут) — компромисс между двумя
// крайностями. Без кеша валидатор бы при каждой проверке токена дёргал
// сеть. С кешем на сутки клиент не заметит ротацию ключей и ещё долго
// будет отвергать токены, подписанные новым ключом. 5 минут — типовой
// компромисс: нагрузка на /pq-jwks в пределах разумного, простой при
// смене ключа короткий.
func (s *Server) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	set, err := s.keys.PublicSet()
	if err != nil {
		s.cfg.Logger.Error("authserver: сборка JWKS", "err", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=300")
	s.writeJSON(w, http.StatusOK, set)
}
