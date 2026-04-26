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
// Реальная полезная нагрузка (grant_type+username+password+scope или
// refresh_token, или отзываемый токен) укладывается в килобайты — 64 КБ
// с большим запасом и при этом не даёт злоумышленнику съесть память сервера.
const maxTokenRequestBody = 64 * 1024

// tokenResponse — успешный ответ эндпоинтов /auth/token и /auth/refresh
// (RFC 6749 §5.1). Поля для refresh-токена опускаются через omitempty,
// если refresh не выпускался.
type tokenResponse struct {
	AccessToken      string `json:"access_token"`
	TokenType        string `json:"token_type"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshToken     string `json:"refresh_token,omitempty"`
	RefreshExpiresIn int    `json:"refresh_expires_in,omitempty"`
	Scope            string `json:"scope,omitempty"`
}

// handleToken — POST /auth/token.
//
// Реализует только grant_type=password (Resource Owner Password Credentials,
// RFC 6749 §4.3). Для прототипа диссертации это самый прямой способ получить
// токен: «логин/пароль на вход — токен на выход», без редиректов и
// authorization code flow. Для реального production OAuth-сервера password
// grant считается deprecated, но эксперимент главы 4 он не искажает.
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
// Принимает grant_type=refresh_token + refresh_token. При успехе помечает
// старый refresh как использованный и выдаёт новую пару (access + новый
// refresh) — это и есть rotation.
//
// Если refresh уже использовался ранее, не существует, отозван, или подпись
// не сходится — отвечаем единственным кодом invalid_grant без подробностей,
// чтобы атакующему не удавалось различать сценарии по ответам сервера.
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

	// Достаём сессию и помечаем её использованной. MarkUsed возвращает false,
	// если сессии нет (возможно, сервер перезапускали и она потерялась)
	// или она уже была использована — это сигнал replay-атаки.
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
// Принимает token (обязательно) и опциональный token_type_hint. По RFC §2.2
// отвечает 200 даже если токен не найден или формата мы не разобрали — это
// предотвращает утечки информации.
func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxTokenRequestBody)
	if err := r.ParseForm(); err != nil {
		// По RFC ошибки разбора параметров — это invalid_request.
		// Здесь это допустимо: тело запроса невалидно структурно.
		s.writeOAuthError(w, http.StatusBadRequest, "invalid_request",
			"не удалось разобрать тело запроса")
		return
	}

	tokenValue := r.PostForm.Get("token")
	hint := r.PostForm.Get("token_type_hint")
	if tokenValue == "" {
		// Сам токен — обязательный параметр (RFC 7009 §2.1).
		s.writeOAuthError(w, http.StatusBadRequest, "invalid_request",
			"требуется параметр token")
		return
	}

	// Сначала разбираем токен и пытаемся понять его тип. Если не получилось —
	// по RFC всё равно отвечаем 200, ничего не трогая в сторах.
	header, claims, _, _, err := pqt.Parse([]byte(tokenValue), token.FormatText)
	if err == nil {
		s.applyRevocation(header, claims, hint)
	}

	w.WriteHeader(http.StatusOK)
}

// applyRevocation удаляет refresh-сессию или добавляет access-jti в чёрный
// список. Решение принимается строго по claim.Kind токена — это поле подписано
// и менять его извне нельзя. Hint из тела запроса используется только в
// единственном случае: токен выпустили до появления Kind (Kind==""), и нам
// нужна подсказка. Иначе hint игнорируется — иначе атакующий мог бы выдать
// чужой access-токен за refresh и обнулить blacklist'инг.
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
	// access, пустой Kind без полезного hint — всё в blacklist.
	s.revoked.Revoke(c.Jti, s.cfg.Now())
}

// issuePair выпускает пару (access, refresh) для пользователя с заданным scope.
// Используется в handleToken (первичный логин) и в handleRefresh (rotation).
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

	// Сессия refresh — для лукапа в /auth/refresh.
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

// issuedToken — внутренний результат issueOne: и сериализованные байты,
// и jti, чтобы не разбирать токен повторно.
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
		Sub:   username,
		Iss:   s.cfg.Issuer,
		Aud:   s.cfg.Issuer, // для прототипа audience = сам issuer
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

// validateOwnRefresh проверяет, что присланный refresh-токен подписан текущим
// сервером, не истёк, не отозван и имеет kind="refresh". Возвращает разобранные
// claims при успехе.
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
		return token.Claims{}, errors.New("kind != refresh")
	}
	return claims, nil
}

// handleJWKS — GET /.well-known/pq-jwks.
//
// Публикует все публичные ключи сервера в формате jwk.Set, чтобы внешние
// валидаторы могли проверять подписи токенов. Cache-Control с коротким
// TTL — компромисс: даём клиентам кешировать, но при ротации ключей не
// застрянем надолго со старым набором.
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
