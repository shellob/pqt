package authserver

import (
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// seedUserSpec описывает одного захардкоженного пользователя: пароль в открытом
// виде и набор разрешённых scope. На старте сервера пароль превращается в bcrypt-hash,
// в памяти сервера plaintext-пароль не остаётся.
//
// Это прототип диссертации, не production: в реальном развёртывании
// пользователи и пароли лежали бы в базе. Для воспроизводимости эксперимента
// глав 4.2–4.6 удобнее иметь фиксированный набор учёток, известный заранее.
type seedUserSpec struct {
	Password string
	Scope    string
}

// seedUsers — четыре захардкоженных пользователя с разными уровнями доступа.
// Их используют тесты и нагрузочные сценарии.
var seedUsers = map[string]seedUserSpec{
	"alice":   {Password: "alice-password-2026", Scope: "read write"},
	"bob":     {Password: "bob-password-2026", Scope: "read"},
	"charlie": {Password: "charlie-password-2026", Scope: "read write admin"},
	"dave":    {Password: "dave-password-2026", Scope: "read"},
}

// User — пользователь в памяти сервера. Хранит хеш пароля, не сам пароль.
type User struct {
	Username     string
	PasswordHash []byte
	Scope        string
}

// UserStore — хранилище seed-пользователей. Не потокобезопасно для записи,
// но писать в него и не предполагается: набор пользователей фиксированный.
type UserStore struct {
	users map[string]User
}

// NewUserStore создаёт хранилище и хеширует пароли всех seed-пользователей.
// bcryptCost задаёт сложность хеширования: production-значение по умолчанию —
// bcrypt.DefaultCost (10), для тестов имеет смысл bcrypt.MinCost (4),
// чтобы старт занимал миллисекунды.
func NewUserStore(bcryptCost int) (*UserStore, error) {
	users := make(map[string]User, len(seedUsers))
	for name, spec := range seedUsers {
		hash, err := bcrypt.GenerateFromPassword([]byte(spec.Password), bcryptCost)
		if err != nil {
			return nil, fmt.Errorf("authserver: bcrypt-хеш пользователя %q: %w", name, err)
		}
		users[name] = User{
			Username:     name,
			PasswordHash: hash,
			Scope:        spec.Scope,
		}
	}
	return &UserStore{users: users}, nil
}

// Authenticate проверяет логин и пароль. Возвращает пользователя при успехе
// и пустую структуру + false при любой неудаче — без различения «нет такого
// пользователя» и «неверный пароль», чтобы не упрощать timing/probing-атаки.
func (s *UserStore) Authenticate(username, password string) (User, bool) {
	u, ok := s.users[username]
	if !ok {
		// Прогоняем bcrypt-сравнение даже при отсутствии пользователя, чтобы
		// время отклика не зависело от существования логина. Используем
		// фиксированный заглушечный хеш, чтобы CompareHashAndPassword отработал.
		_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(password))
		return User{}, false
	}
	if err := bcrypt.CompareHashAndPassword(u.PasswordHash, []byte(password)); err != nil {
		return User{}, false
	}
	return u, true
}

// dummyHash — заглушечный bcrypt-хеш константного значения. Используется в
// Authenticate для нечувствительности времени отклика к существованию логина.
// Сам хеш сгенерирован один раз и зашит в код; пароль "dummy" с cost=4.
var dummyHash = []byte("$2a$04$j7s5oCNYvYG8gwx3RPLKPOkWvK8VoPJoCEd0Bs4WlcWyCM38P5jZK")
