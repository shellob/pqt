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

// KeyEntry — одна запись в хранилище ключей сервера. Содержит приватный
// и парный публичный ключ (это два разных Go-объекта, хотя получаются
// они из одной криптографической пары) и идентификатор kid.
//
// kid (key ID) — это короткое имя, по которому клиенты отличают один
// ключ сервера от другого. Когда сервер выпускает токен, он кладёт kid
// в заголовок токена; когда клиент-валидатор проверяет токен, он по
// kid находит в JWKS-наборе нужный публичный ключ. Без kid нельзя
// провести плавную смену ключей: пока в обороте есть токены, подписанные
// старым ключом, нельзя его удалить — но и подписывать новые им уже
// нельзя.
type KeyEntry struct {
	Kid     string
	Private keys.PrivateKey
	Public  keys.PublicKey
}

// KeyStore — все ключи, которые сервер использует в данный момент. На
// каждый kid хранится одна запись KeyEntry; один из них помечен как
// «по умолчанию» — это тот ключ, которым сервер подписывает новые
// токены. Остальные нужны для проверки подписей старых токенов,
// которые уже находятся в обращении.
//
// Структура неизменяемая после создания: ключи загружаются один раз
// при старте сервера и больше не меняются. Поэтому никаких мьютексов
// внутри нет — параллельные чтения безопасны сами по себе.
type KeyStore struct {
	keys       map[string]*KeyEntry
	defaultKid string
}

// LoadOrInit инициализирует KeyStore из директории dir.
//
// Логика такая:
//
//  1. Если в dir уже лежат файлы *.priv.jwk.json — все они загружаются.
//     Каждый файл — это один JWK с приватным ключом; поле kid в JWK
//     должно быть непустым (по нему запись регистрируется в map).
//     Имя файла используется только для поиска по диску; идентификатор
//     ключа берётся из самого JWK.
//  2. Если dir не существует или в нём нет ни одного приватного
//     JWK-файла — KeyStore генерирует один свежий ключ алгоритма
//     generateAlg, сохраняет его в dir как пару (приватный + публичный
//     JWK-файлы) и продолжает с этим единственным ключом.
//
// Параметр defaultKid задаёт, какой ключ из загруженных будет помечен
// как «по умолчанию» (для подписи новых токенов). Если defaultKid
// пустой — берётся первый по алфавитному порядку kid (это
// детерминированно, не зависит от того, в каком порядке ОС вернула
// файлы при чтении директории). Если defaultKid задан, но такого kid
// в наборе нет — это ошибка.
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

// Default возвращает «ключ по умолчанию» — тот, которым сервер
// подписывает свежие токены при выпуске. Изменить выбор после старта
// нельзя; чтобы переключиться на другой ключ, сервер нужно
// перезапустить с другим PQT_DEFAULT_KID.
func (s *KeyStore) Default() *KeyEntry {
	return s.keys[s.defaultKid]
}

// ByKid ищет ключ по идентификатору. Используется на стороне сервера
// при /auth/refresh: сервер должен проверить подпись присланного
// refresh-токена своим же ключом — но не обязательно текущим default,
// потому что во время ротации ключей токен мог быть подписан старым.
// Поэтому кид берётся из заголовка токена и им ищется правильная
// запись.
func (s *KeyStore) ByKid(kid string) (*KeyEntry, bool) {
	e, ok := s.keys[kid]
	return e, ok
}

// PublicSet собирает публичные части всех ключей в jwk.Set, готовый к
// публикации на эндпоинте /.well-known/pq-jwks. Сортировка по kid
// делает порядок ответа детерминированным — это удобно для тестов и
// для того, чтобы клиенты могли (если хотят) кешировать ответ по
// его содержимому.
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

// loadKeysFromDir читает все файлы *.priv.jwk.json из dir и собирает
// из них набор KeyEntry. Если dir не существует — это не ошибка,
// просто возвращается пустая map; решение «генерить ключ или нет»
// принимается выше, в LoadOrInit.
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
		// gosec предупреждает о чтении файла по переменному пути, но
		// здесь dir указывает оператор сервера через PQT_KEYS_DIR —
		// это часть конфигурации, а не пользовательский ввод.
		data, err := os.ReadFile(path) //nolint:gosec
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

// generateAndSave создаёт свежий ключ нужного алгоритма и сохраняет
// его пару (приватный JWK + публичный JWK) в dir. kid формируется из
// текущей даты в UTC, так что при первом запуске сервера получается
// что-то вроде "default-20260428-103045".
//
// Права на директорию 0o700 (только владелец может зайти) — приватные
// ключи не должны быть доступны другим пользователям системы. Права
// на файлы 0o600 ставятся внутри writeJWKFile.
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

// generatePrivate выбирает нужный конструктор из пакета keys в
// зависимости от алгоритма. Логика дублируется в cmd/pqt-cli/keygen.go,
// но общий хелпер мы пока не выносили: всего две точки использования и
// в каждой свой контекст ошибок.
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

// writeJWKFile записывает один JWK в файл с правами 0o600 (читать и
// писать может только владелец процесса). Для приватных ключей это
// важно: даже если на сервер зайдёт другой пользователь системы, он
// не сможет прочитать ключ.
//
// JSON пишется с отступами (MarshalIndent) — JWK-файлы обычно мелкие,
// размер не критичен, а смотреть в редакторе с отступами удобнее.
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
