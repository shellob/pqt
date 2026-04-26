package authserver

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"pqt/jwk"
	"pqt/keys"
)

// KeyEntry — запись в KeyStore: пара ключей (приватный и парный публичный)
// и идентификатор kid, под которым она зарегистрирована.
type KeyEntry struct {
	Kid     string
	Private keys.PrivateKey
	Public  keys.PublicKey
}

// KeyStore — набор ключей сервера. На каждый kid один KeyEntry; один из них
// помечен как «по умолчанию» — именно им сервер подписывает новые токены.
//
// Не потокобезопасно для записи, но это и не требуется: набор ключей
// фиксируется при старте сервера.
type KeyStore struct {
	keys       map[string]*KeyEntry
	defaultKid string
}

// LoadOrInit инициализирует KeyStore из директории dir.
//
// Если в dir уже лежат файлы *.priv.jwk.json — они загружаются. Каждый файл
// должен иметь непустое поле kid в JWK; именно по этому полю регистрируется
// запись (имя файла используется только для поиска).
//
// Если dir не существует или в нём нет приватных JWK-файлов — KeyStore
// генерирует один свежий ключ алгоритма generateAlg и сохраняет его в dir
// (директория при необходимости создаётся).
//
// Параметр defaultKid задаёт ключ для подписи новых токенов. Если он пустой,
// берётся первый по алфавитному порядку kid из загруженных. Если задан, но
// такого kid нет — функция возвращает ошибку.
func LoadOrInit(dir, defaultKid string, generateAlg keys.Alg) (*KeyStore, error) {
	loaded, err := loadKeysFromDir(dir)
	if err != nil {
		return nil, err
	}

	if len(loaded) == 0 {
		entry, err := generateAndSave(dir, generateAlg)
		if err != nil {
			return nil, err
		}
		loaded = map[string]*KeyEntry{entry.Kid: entry}
	}

	resolvedKid := defaultKid
	if resolvedKid == "" {
		// Берём первый kid по алфавиту — детерминированно и не зависит от
		// порядка чтения файлов из ОС.
		kids := make([]string, 0, len(loaded))
		for k := range loaded {
			kids = append(kids, k)
		}
		sort.Strings(kids)
		resolvedKid = kids[0]
	}
	if _, ok := loaded[resolvedKid]; !ok {
		return nil, fmt.Errorf("authserver: ключ с kid %q не найден в %s", resolvedKid, dir)
	}

	return &KeyStore{keys: loaded, defaultKid: resolvedKid}, nil
}

// Default возвращает ключ, которым сервер подписывает новые токены.
func (s *KeyStore) Default() *KeyEntry {
	return s.keys[s.defaultKid]
}

// ByKid ищет ключ по идентификатору. Используется при поиске ключа для
// проверки подписи (на случай, когда в наборе несколько активных ключей).
func (s *KeyStore) ByKid(kid string) (*KeyEntry, bool) {
	e, ok := s.keys[kid]
	return e, ok
}

// PublicSet собирает публичные части всех ключей в jwk.Set, готовый к публикации
// на эндпоинте /.well-known/pq-jwks. Ключи отсортированы по kid для
// детерминированного вывода.
func (s *KeyStore) PublicSet() (jwk.Set, error) {
	kids := make([]string, 0, len(s.keys))
	for k := range s.keys {
		kids = append(kids, k)
	}
	sort.Strings(kids)

	out := make([]jwk.JWK, 0, len(kids))
	for _, kid := range kids {
		j, err := jwk.MarshalPublic(s.keys[kid].Public)
		if err != nil {
			return jwk.Set{}, fmt.Errorf("authserver: сериализация публичного ключа %q: %w", kid, err)
		}
		j.Kid = kid
		out = append(out, j)
	}
	return jwk.Set{Keys: out}, nil
}

// loadKeysFromDir читает все файлы *.priv.jwk.json из dir и собирает из них
// набор KeyEntry. Если dir не существует — это не ошибка, просто возвращается
// пустая map (выше по стеку решат, генерить ли ключ).
func loadKeysFromDir(dir string) (map[string]*KeyEntry, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]*KeyEntry{}, nil
		}
		return nil, fmt.Errorf("authserver: чтение директории ключей %q: %w", dir, err)
	}

	out := make(map[string]*KeyEntry)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".priv.jwk.json") {
			continue
		}

		path := filepath.Join(dir, name)
		data, err := os.ReadFile(path) //nolint:gosec // путь под контролем оператора, не пользователя
		if err != nil {
			return nil, fmt.Errorf("authserver: чтение %q: %w", path, err)
		}

		var j jwk.JWK
		if err := json.Unmarshal(data, &j); err != nil {
			return nil, fmt.Errorf("authserver: разбор JWK %q: %w", path, err)
		}
		if j.Kid == "" {
			return nil, fmt.Errorf("authserver: пустой kid в %q", path)
		}

		priv, err := jwk.ParsePrivate(j)
		if err != nil {
			return nil, fmt.Errorf("authserver: разбор приватного ключа %q: %w", path, err)
		}

		out[j.Kid] = &KeyEntry{
			Kid:     j.Kid,
			Private: priv,
			Public:  priv.Public(),
		}
	}
	return out, nil
}

// generateAndSave создаёт свежий ключ нужного алгоритма и сохраняет его пару
// (приватный + публичный JWK) в dir. kid формируется из текущей даты в UTC.
func generateAndSave(dir string, alg keys.Alg) (*KeyEntry, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("authserver: создание директории ключей %q: %w", dir, err)
	}

	priv, err := generatePrivate(alg)
	if err != nil {
		return nil, err
	}

	kid := "default-" + time.Now().UTC().Format("20060102-150405")

	privJWK, err := jwk.MarshalPrivate(priv)
	if err != nil {
		return nil, fmt.Errorf("authserver: сериализация приватного ключа: %w", err)
	}
	privJWK.Kid = kid

	pubJWK, err := jwk.MarshalPublic(priv.Public())
	if err != nil {
		return nil, fmt.Errorf("authserver: сериализация публичного ключа: %w", err)
	}
	pubJWK.Kid = kid

	if err := writeJWKFile(filepath.Join(dir, kid+".priv.jwk.json"), privJWK); err != nil {
		return nil, err
	}
	if err := writeJWKFile(filepath.Join(dir, kid+".pub.jwk.json"), pubJWK); err != nil {
		return nil, err
	}

	return &KeyEntry{Kid: kid, Private: priv, Public: priv.Public()}, nil
}

// generatePrivate выбирает нужный конструктор из пакета keys в зависимости
// от алгоритма. Дублирует логику из cmd/pqt-cli/keygen.go; общий хелпер
// мы выносить пока не стали — всего две точки использования и разные
// контексты ошибок.
func generatePrivate(alg keys.Alg) (keys.PrivateKey, error) {
	switch alg {
	case keys.AlgECDSAP256:
		k, err := keys.GenerateECDSA()
		if err != nil {
			return nil, fmt.Errorf("authserver: генерация ECDSA: %w", err)
		}
		return k, nil
	case keys.AlgMLDSA44, keys.AlgMLDSA65, keys.AlgMLDSA87:
		k, err := keys.GenerateMLDSA(alg)
		if err != nil {
			return nil, fmt.Errorf("authserver: генерация %s: %w", alg, err)
		}
		return k, nil
	case keys.AlgHybridECDSAMLDSA44:
		return generateHybrid(keys.AlgMLDSA44)
	case keys.AlgHybridECDSAMLDSA65:
		return generateHybrid(keys.AlgMLDSA65)
	case keys.AlgHybridECDSAMLDSA87:
		return generateHybrid(keys.AlgMLDSA87)
	default:
		return nil, fmt.Errorf("authserver: неизвестный алгоритм %q", alg)
	}
}

func generateHybrid(pqAlg keys.Alg) (keys.PrivateKey, error) {
	k, err := keys.GenerateHybrid(pqAlg)
	if err != nil {
		return nil, fmt.Errorf("authserver: генерация гибрида с %s: %w", pqAlg, err)
	}
	return k, nil
}

func writeJWKFile(path string, j jwk.JWK) error {
	data, err := json.MarshalIndent(j, "", "  ")
	if err != nil {
		return fmt.Errorf("authserver: сериализация JWK: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("authserver: запись %q: %w", path, err)
	}
	return nil
}
