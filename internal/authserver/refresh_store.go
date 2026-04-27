package authserver

import (
	"sync"
	"time"
)

// RefreshSession — запись о выпущенном refresh-токене.
//
// JTI берётся из самого токена (claim jti) и служит ключом в RefreshStore.
// Сервер хранит сессию, чтобы при обращении на /auth/refresh:
//   - убедиться, что присланный refresh-токен действительно выпускался
//     этим сервером (а не подделан);
//   - привязать обновление к конкретному пользователю и его scope;
//   - заметить повторное использование уже отыгранного refresh — это
//     типичный признак компрометации (см. RFC 6749 §10.4 про ротацию).
type RefreshSession struct {
	JTI       string
	Username  string
	Scope     string
	IssuedAt  time.Time
	ExpiresAt time.Time

	// Used становится true после первой успешной ротации. Если кто-то
	// приходит со ссылкой на ту же сессию ещё раз — это либо повторный
	// запрос клиента после сетевого сбоя (мы ему просто откажем), либо
	// компрометация: украденный refresh снова пускают в дело. В нашем
	// прототипе мы реагируем минимально — отказываем и пишем warn в лог;
	// каскадной инвалидации цепочки токенов нет.
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

// Save кладёт новую сессию в хранилище. Принимает значение, а не указатель,
// и копирует его внутрь — так вызывающий код не сможет случайно
// поменять данные хранилища, держа ссылку на ту же структуру. Перезапись
// по существующему jti не предполагается (jti уникален по построению),
// но если случится — последняя запись побеждает.
func (s *RefreshStore) Save(sess RefreshSession) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := sess
	s.sessions[sess.JTI] = &cp
}

// Get возвращает сессию по jti. Если такого jti нет — bool=false.
func (s *RefreshStore) Get(jti string) (*RefreshSession, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sess, ok := s.sessions[jti]
	if !ok {
		return nil, false
	}
	// Возвращаем копию, чтобы вызывающий код не смог случайно поменять
	// внутреннее состояние хранилища через возвращённый указатель.
	cp := *sess
	return &cp, true
}

// MarkUsed помечает сессию использованной в рамках ротации. Возвращает true,
// если пометка прошла успешно; false — если сессии нет или она уже была
// использована раньше (это и есть сигнал о повторном проигрывании
// refresh-токена).
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

// Delete удаляет сессию (используется при отзыве refresh-токена). Если
// такой сессии нет — это не ошибка: эндпоинт /auth/revoke по RFC 7009 §2.2
// обязан возвращать успех в любом случае.
func (s *RefreshStore) Delete(jti string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, jti)
}
