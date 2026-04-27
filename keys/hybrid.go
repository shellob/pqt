package keys

import (
	"encoding/binary"
	"fmt"
	"math"

	"golang.org/x/sync/errgroup"
)

// hybridLengthPrefixSize — сколько байт в начале гибридной подписи отведено
// под длину её «классической части» (uint16, big-endian, то есть от 0 до
// 65535). Это технический параметр формата гибридной подписи.
//
// Зачем это вообще нужно. ECDSA-подпись имеет переменную длину (около
// 70-72 байт, зависит от значений r и s, которые вышли при подписи).
// ML-DSA-подпись фиксированной длины. Если просто склеить ECDSA + ML-DSA
// без разделителя, при разборе будет непонятно, где заканчивается ECDSA
// и начинается ML-DSA. Поэтому в начало кладётся 2 байта с длиной
// классической части: разбор сразу знает, сколько байт отрезать на ECDSA,
// остальное — ML-DSA.
const hybridLengthPrefixSize = 2

// HybridPrivateKey — гибридная пара ключей: классический ECDSA P-256 +
// постквантовый ML-DSA. Структура хранит обе половины как готовые
// PrivateKey-интерфейсы, чтобы не дублировать код подписи и проверки.
//
// Идея гибрида (раздел 2.3 спецификации PQ-AT): один и тот же текст
// подписывается обоими ключами; токен считается валидным только если
// **обе** подписи проверились. Так мы страхуемся от двух разных угроз:
// если квантовый компьютер сломает ECDSA — спасёт ML-DSA; если в
// ML-DSA найдут уязвимость (алгоритм молодой) — спасёт ECDSA. Чтобы
// обойти такую защиту, атакующему нужно сломать сразу оба алгоритма,
// что качественно сложнее, чем сломать один.
type HybridPrivateKey struct {
	classic PrivateKey
	pq      PrivateKey
	alg     Alg
}

// HybridPublicKey — парный гибридный публичный ключ. Содержит публичные
// половины обеих пар (ECDSA и ML-DSA) и идентификатор гибридного
// алгоритма.
type HybridPublicKey struct {
	classic PublicKey
	pq      PublicKey
	alg     Alg
}

// NewHybrid собирает гибридную пару из готовых классической и
// постквантовой ключей. Используется, например, при загрузке ключа
// из JWK: каждая половина пары приходит отдельной структурой, и нам
// нужно склеить их в гибрид.
//
// Допустимая комбинация одна — ECDSA P-256 в роли классики и любая
// из mldsa44/65/87 в роли постквантовой. Если что-то не из этого
// набора, вернётся ErrAlgMismatch.
func NewHybrid(classic, pq PrivateKey) (*HybridPrivateKey, error) {
	alg, err := combineHybridAlg(classic.Algorithm(), pq.Algorithm())
	if err != nil {
		return nil, err
	}
	return &HybridPrivateKey{classic: classic, pq: pq, alg: alg}, nil
}

// NewHybridPublic — то же самое, но для публичных ключей. Используется
// на стороне проверки токена: получили JWK с двумя половинами публичных
// ключей — собрали в гибридный публичный.
func NewHybridPublic(classic, pq PublicKey) (*HybridPublicKey, error) {
	alg, err := combineHybridAlg(classic.Algorithm(), pq.Algorithm())
	if err != nil {
		return nil, err
	}
	return &HybridPublicKey{classic: classic, pq: pq, alg: alg}, nil
}

// GenerateHybrid создаёт свежую гибридную пару. Классическая половина
// всегда ECDSA P-256 (других вариантов классики PQ-AT не предусматривает),
// уровень постквантовой части задаётся параметром: AlgMLDSA44, AlgMLDSA65
// (целевой) или AlgMLDSA87.
//
// Каждая половина генерируется независимо, своим источником случайности
// (внутри стандартных конструкторов GenerateECDSA и GenerateMLDSA). Для
// безопасности гибрида важно, чтобы ключи действительно были независимы:
// зная один, нельзя было бы предсказать второй.
func GenerateHybrid(pqAlg Alg) (*HybridPrivateKey, error) {
	classic, err := GenerateECDSA()
	if err != nil {
		return nil, err
	}
	pq, err := GenerateMLDSA(pqAlg)
	if err != nil {
		return nil, err
	}
	return NewHybrid(classic, pq)
}

// combineHybridAlg проверяет, что переданная пара алгоритмов разрешена,
// и возвращает идентификатор соответствующего гибрида. Используется
// конструкторами NewHybrid и NewHybridPublic как общий код проверки.
func combineHybridAlg(classic, pq Alg) (Alg, error) {
	if classic != AlgECDSAP256 {
		return "", fmt.Errorf("%w: классическая часть гибрида должна быть %s, получено %s",
			ErrAlgMismatch, AlgECDSAP256, classic)
	}
	switch pq {
	case AlgMLDSA44:
		return AlgHybridECDSAMLDSA44, nil
	case AlgMLDSA65:
		return AlgHybridECDSAMLDSA65, nil
	case AlgMLDSA87:
		return AlgHybridECDSAMLDSA87, nil
	default:
		return "", fmt.Errorf("%w: постквантовая часть гибрида должна быть ML-DSA, получено %s",
			ErrAlgMismatch, pq)
	}
}

// Sign подписывает сообщение обеими половинами гибрида и склеивает
// результаты в одну итоговую подпись с длиной классической части в
// начале (см. описание hybridLengthPrefixSize).
//
// Сейчас две подписи делаются последовательно: сначала ECDSA, потом
// ML-DSA. Делать их параллельно через горутины не стали — с одной
// стороны, ECDSA-подпись быстрая (десятки микросекунд), с другой —
// в большинстве сценариев Issue делается редко и поодиночке, и
// выигрыш от параллельности был бы неощутим. У Verify ситуация другая
// (см. метод Verify ниже), там параллельность есть.
func (p *HybridPrivateKey) Sign(message []byte) ([]byte, error) {
	classicSig, err := p.classic.Sign(message)
	if err != nil {
		return nil, fmt.Errorf("keys: гибрид, классическая подпись: %w", err)
	}
	pqSig, err := p.pq.Sign(message)
	if err != nil {
		return nil, fmt.Errorf("keys: гибрид, PQ-подпись: %w", err)
	}
	return joinHybridSignature(classicSig, pqSig)
}

// Public возвращает парный гибридный публичный ключ — собранный из
// публичных половин ECDSA и ML-DSA.
func (p *HybridPrivateKey) Public() PublicKey {
	return &HybridPublicKey{
		classic: p.classic.Public(),
		pq:      p.pq.Public(),
		alg:     p.alg,
	}
}

// Algorithm возвращает идентификатор гибридного алгоритма.
func (p *HybridPrivateKey) Algorithm() Alg { return p.alg }

// Components возвращает классическую и постквантовую половины приватного
// ключа отдельно. Нужен пакету jwk: при сохранении гибрида в JWK мы
// сохраняем обе половины как два «обычных» JWK (рядом, в массиве
// components), и для этого нужен доступ к каждой по отдельности.
func (p *HybridPrivateKey) Components() (classic, pq PrivateKey) {
	return p.classic, p.pq
}

// Verify проверяет гибридную подпись. Сначала разбирает её на две
// половины (по длине классической части в префиксе), потом сверяет
// каждую — параллельно, через golang.org/x/sync/errgroup.
//
// Параллельность здесь оправдана: ML-DSA-Verify дороже ECDSA-Verify
// на постквантовых уровнях 65/87 (см. главу 4.4 диссертации). Если
// прогонять две проверки последовательно, общее время = ECDSA + ML-DSA;
// если параллельно — общее время ≈ max(ECDSA, ML-DSA), то есть почти
// одна ML-DSA-проверка. Для mldsa65/87 это даёт +5..9% к скорости,
// для mldsa44 параллельность не выигрывает (overhead errgroup
// перевешивает разницу).
//
// Токен считается валидным только если обе проверки прошли (это
// «логическое И» в спецификации PQ-AT, раздел 2.3). errgroup.Wait
// возвращает первую же ошибку из любой горутины — то есть достаточно
// одной неудачной половины, чтобы отвергнуть токен целиком.
func (v *HybridPublicKey) Verify(message, signature []byte) error {
	classicSig, pqSig, err := splitHybridSignature(signature)
	if err != nil {
		return err
	}
	var eg errgroup.Group
	eg.Go(func() error {
		if err := v.classic.Verify(message, classicSig); err != nil {
			return fmt.Errorf("keys: гибрид, проверка классической подписи: %w", err)
		}
		return nil
	})
	eg.Go(func() error {
		if err := v.pq.Verify(message, pqSig); err != nil {
			return fmt.Errorf("keys: гибрид, проверка PQ-подписи: %w", err)
		}
		return nil
	})
	return eg.Wait()
}

// VerifySequential — то же, что Verify, но обе половины проверяются
// последовательно, без горутин. Существует исключительно ради бенчмарков
// в главе 4.4 диссертации: сравниваются скорости sequential vs parallel,
// и для honest-сравнения нужны обе реализации с одинаковой логикой
// разбора подписи.
//
// В production-коде использовать Verify, не VerifySequential.
func (v *HybridPublicKey) VerifySequential(message, signature []byte) error {
	classicSig, pqSig, err := splitHybridSignature(signature)
	if err != nil {
		return err
	}
	if err := v.classic.Verify(message, classicSig); err != nil {
		return fmt.Errorf("keys: гибрид, проверка классической подписи: %w", err)
	}
	if err := v.pq.Verify(message, pqSig); err != nil {
		return fmt.Errorf("keys: гибрид, проверка PQ-подписи: %w", err)
	}
	return nil
}

// Algorithm возвращает идентификатор гибридного алгоритма.
func (v *HybridPublicKey) Algorithm() Alg { return v.alg }

// Components возвращает классическую и постквантовую половины публичного
// ключа отдельно. Нужно для сериализации в JWK (см. описание у
// HybridPrivateKey.Components).
func (v *HybridPublicKey) Components() (classic, pq PublicKey) {
	return v.classic, v.pq
}

// joinHybridSignature склеивает две подписи в одну итоговую гибридную:
//
//	[2 байта длины classic, big-endian] [classic-байты] [pq-байты]
//
// Если классическая часть оказывается длиннее 65535 байт, в uint16 она
// уже не помещается — это структурная ошибка, отдаём ErrMalformedSignature.
// На практике для ECDSA P-256 такого случиться не может (там 70-72 байта),
// но проверка стоит на случай, если в гибрид однажды подсунут другой
// классический алгоритм.
func joinHybridSignature(classic, pq []byte) ([]byte, error) {
	if len(classic) > math.MaxUint16 {
		return nil, fmt.Errorf("%w: классическая подпись слишком длинная (%d > %d)",
			ErrMalformedSignature, len(classic), math.MaxUint16)
	}
	classicLen := uint16(len(classic) & math.MaxUint16) // длина проверена выше
	out := make([]byte, hybridLengthPrefixSize+len(classic)+len(pq))
	binary.BigEndian.PutUint16(out[:hybridLengthPrefixSize], classicLen)
	copy(out[hybridLengthPrefixSize:], classic)
	copy(out[hybridLengthPrefixSize+len(classic):], pq)
	return out, nil
}

// splitHybridSignature делает обратное: получает на вход байты гибридной
// подписи, читает длину классической части из первых двух байт и
// разрезает остаток на classic-часть и pq-часть.
//
// Все ошибки на этом этапе — структурные, до криптографической проверки
// мы ещё не дошли. Поэтому везде ErrMalformedSignature, не
// ErrInvalidSignature.
func splitHybridSignature(sig []byte) (classic, pq []byte, err error) {
	if len(sig) < hybridLengthPrefixSize {
		// Подпись короче, чем нужно даже для записи длины классической
		// части. Это совсем мусор.
		return nil, nil, fmt.Errorf("%w: подпись короче префикса длины (%d < %d)",
			ErrMalformedSignature, len(sig), hybridLengthPrefixSize)
	}
	classicLen := int(binary.BigEndian.Uint16(sig[:hybridLengthPrefixSize]))
	if classicLen == 0 {
		// Длина классической части указана нулём. Это технически возможно
		// в подписи, но валидной ECDSA P-256-подписи длины 0 не бывает,
		// значит подпись битая.
		return nil, nil, fmt.Errorf("%w: длина классической подписи равна нулю", ErrMalformedSignature)
	}
	end := hybridLengthPrefixSize + classicLen
	if end > len(sig) {
		// Длина классической части указывает за пределы всей подписи —
		// то есть «по этой длине» места в буфере уже нет. Подпись битая
		// или подделана.
		return nil, nil, fmt.Errorf("%w: длина классической подписи %d больше всей подписи (%d байт)",
			ErrMalformedSignature, classicLen, len(sig))
	}
	if end == len(sig) {
		// Длина классической части указывает ровно в конец буфера — это
		// значит, что для постквантовой части не осталось ни байта.
		// Гибрид без обеих половин не имеет смысла.
		return nil, nil, fmt.Errorf("%w: PQ-подпись отсутствует", ErrMalformedSignature)
	}
	return sig[hybridLengthPrefixSize:end], sig[end:], nil
}
