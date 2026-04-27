package authserver

import (
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// seedUserSpec описывает одного захардкоженного пользователя: пароль в
// открытом виде и набор разрешённых scope. На старте сервера пароль
// прогоняется через bcrypt, и в памяти остаётся только хеш — открытый
// пароль не сохраняется.
//
// Это прототип диссертации, а не боевой сервер: в реальном развёртывании
// пользователи и пароли лежали бы в базе данных. Для воспроизводимости
// эксперимента глав 4.2–4.6 удобнее иметь фиксированный набор учёток,
// известный заранее.
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
	users     map[string]User
	dummyHash []byte
}

// NewUserStore создаёт хранилище и прогоняет пароли всех seed-пользователей
// через bcrypt. Параметр bcryptCost задаёт сложность хеширования: значение
// по умолчанию для боевой среды — bcrypt.DefaultCost (10), для тестов имеет
// смысл bcrypt.MinCost (4), чтобы старт занимал миллисекунды.
//
// Вместе с пользователями хешируется заглушка. Её мы используем, когда в
// Authenticate приходит несуществующий логин — чтобы время ответа не
// зависело от того, есть пользователь в базе или нет. Хеш заглушки
// генерируется с тем же cost, что и реальные хеши — иначе атакующий по
// времени отклика моментально отличит «логин есть» от «логина нет».
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

	dummy, err := bcrypt.GenerateFromPassword([]byte("dummy"), bcryptCost)
	if err != nil {
		return nil, fmt.Errorf("authserver: bcrypt-хеш заглушки: %w", err)
	}

	return &UserStore{users: users, dummyHash: dummy}, nil
}

// Authenticate проверяет логин и пароль. Возвращает пользователя при успехе
// и пустую структуру + false в любой неудачной ситуации — без различения
// «нет такого пользователя» и «пароль неверный». Это сделано специально:
// иначе атакующий по разнице ответов или времени отклика мог бы перебирать
// логины и понимать, какие из них существуют (probing-атака).
func (s *UserStore) Authenticate(username, password string) (User, bool) {
	u, ok := s.users[username]
	if !ok {
		// Прогоняем bcrypt-сравнение с заглушкой — той же сложности, что и
		// реальные хеши. Если этого не делать, время отклика на
		// несуществующий логин будет заметно меньше, чем на существующий,
		// и атакующий перечислит логины по таймингу.
		_ = bcrypt.CompareHashAndPassword(s.dummyHash, []byte(password))
		return User{}, false
	}
	if err := bcrypt.CompareHashAndPassword(u.PasswordHash, []byte(password)); err != nil {
		return User{}, false
	}
	return u, true
}
