package authserver

import (
	"sync"
	"time"
)

// RevocationStore — чёрный список идентификаторов токенов (claim jti).
//
// Если jti здесь — соответствующий access-токен считается отозванным,
// и Validator (через ValidateOptions.IsRevoked) обязан его отвергать.
//
// Хранилище in-memory; при перезапуске сервера чёрный список обнуляется.
// Это допустимо для прототипа: токены живут 15 минут и так, а персистентность
// и распределённый кэш — задачи production-эквивалента.
type RevocationStore struct {
	mu      sync.RWMutex
	revoked map[string]time.Time // jti → когда отозвали
}

// NewRevocationStore создаёт пустое хранилище отзывов.
func NewRevocationStore() *RevocationStore {
	return &RevocationStore{revoked: make(map[string]time.Time)}
}

// Revoke добавляет jti в чёрный список с пометкой текущего времени.
// Повторный вызов перезаписывает время — это безопасно.
func (s *RevocationStore) Revoke(jti string, at time.Time) {
	if jti == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revoked[jti] = at
}

// IsRevoked отвечает на вопрос «этот jti в чёрном списке?». Сигнатура совпадает
// с pqt.ValidateOptions.IsRevoked, поэтому метод можно передавать туда напрямую.
func (s *RevocationStore) IsRevoked(jti string) bool {
	if jti == "" {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.revoked[jti]
	return ok
}
