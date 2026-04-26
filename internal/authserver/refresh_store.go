package authserver

import (
	"sync"
	"time"
)

// RefreshSession — запись о выпущенном refresh-токене.
//
// jti берётся из самого токена (claim jti) и используется ключом в RefreshStore.
// Сервер хранит сессию, чтобы при /auth/refresh можно было:
//   - убедиться, что refresh-токен действительно выпускался этим сервером;
//   - привязать обновление к конкретному пользователю и его scope;
//   - детектировать повторное использование уже использованного refresh —
//     это типичный признак компрометации (rotation, RFC 6749 §10.4).
type RefreshSession struct {
	JTI       string
	Username  string
	Scope     string
	IssuedAt  time.Time
	ExpiresAt time.Time

	// Used помечается при первом успешном rotation. Если кто-то приходит
	// со ссылкой на ту же запись повторно — это либо повторный запрос
	// клиента после сетевого сбоя (тогда ему просто откажем), либо
	// компрометация. Без сложной chain-инвалидации — просто отказ + лог.
	Used bool
}

// RefreshStore — потокобезопасное in-memory хранилище refresh-сессий.
type RefreshStore struct {
	mu       sync.RWMutex
	sessions map[string]*RefreshSession
}

// NewRefreshStore создаёт пустое хранилище refresh-сессий.
func NewRefreshStore() *RefreshStore {
	return &RefreshStore{sessions: make(map[string]*RefreshSession)}
}

// Save кладёт новую сессию в хранилище. Принимает значение, копию которого
// и хранит — это защищает store от случайных мутаций со стороны вызывающего
// кода. Перезапись по тому же jti не предполагается (jti уникален по
// построению), но если случится — поведение «последний победил».
func (s *RefreshStore) Save(sess RefreshSession) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := sess
	s.sessions[sess.JTI] = &cp
}

// Get возвращает сессию по jti.
func (s *RefreshStore) Get(jti string) (*RefreshSession, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sess, ok := s.sessions[jti]
	if !ok {
		return nil, false
	}
	// Возвращаем копию, чтобы caller случайно не мутировал хранилище.
	cp := *sess
	return &cp, true
}

// MarkUsed помечает сессию как использованную в рамках rotation.
// Возвращает true, если сессия успешно помечена; false, если её нет или
// она уже была использована.
func (s *RefreshStore) MarkUsed(jti string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[jti]
	if !ok || sess.Used {
		return false
	}
	sess.Used = true
	return true
}

// Delete удаляет сессию (используется при revoke refresh-токена).
// Если такой сессии нет — это не ошибка: revoke-эндпоинт по RFC 7009 §2.2
// должен возвращать успех в любом случае.
func (s *RefreshStore) Delete(jti string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, jti)
}
