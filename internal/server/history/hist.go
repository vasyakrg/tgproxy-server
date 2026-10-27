// Package history — история метрик (samples_10s / samples_5m) и журнал ошибок
// (architecture §7). Горячий путь пишет только в память (Collector, ErrorLog);
// в БД всё уходит из фоновых горутин.
package history

import "time"

// AggregateID — agent_id строки-агрегата «все агенты» в samples_*.
// Пустая строка не подходит: HistoryRepo.Range("") означает «все строки».
const AggregateID = "*"

// Шаги разрешений.
const (
	Step10s = 10 * time.Second
	Step5m  = 5 * time.Minute
)

// LatencyBoundsMs — верхние границы бакетов гистограммы латентности, мс.
// Бакетов на один больше: последний — «больше последней границы».
// Менять можно только надмножеством прежних границ: Sample.Buckets хранится в БД как JSON,
// строки старой длины при чтении перекладываются в новые бакеты (NormalizeBuckets).
//
// Границы 150/200/300/400/750 добавлены, чтобы p95 не схлопывался в 242 мс (интерполяция
// внутри широкого бакета 100–250 при единицах запросов): типичные латентности Telegram
// 100–500 мс теперь делятся на бакеты шириной 50–100 мс.
var LatencyBoundsMs = []float64{5, 10, 25, 50, 100, 150, 200, 250, 300, 400, 500, 750, 1000, 2500, 5000, 10000, 30000}

// legacyBoundsMs — границы до добавления 150/200/300/400/750 (13 бакетов).
var legacyBoundsMs = []float64{5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000, 30000}

// MinP95Samples — меньше стольких запросов в окне p95 считается статистически ненадёжным
// («мало данных» в UI).
const MinP95Samples = 20

// NumBuckets — длина Sample.Buckets.
func NumBuckets() int { return len(LatencyBoundsMs) + 1 }

// NormalizeBuckets приводит гистограмму к текущей длине NumBuckets. Строки в прежнем формате
// (legacyBoundsMs) раскладываются по новым бакетам: новые границы — надмножество старых,
// поэтому каждый старый бакет целиком попадает в новый с той же верхней границей.
// Гистограмма текущей длины возвращается как есть; прочие длины дополняются нулями/усекаются.
func NormalizeBuckets(b []int64) []int64 {
	n := NumBuckets()
	switch {
	case len(b) == n:
		return b
	case len(b) == len(legacyBoundsMs)+1:
		out := make([]int64, n)
		j := 0
		for i, c := range b {
			if i == len(legacyBoundsMs) { // переполняющий бакет
				out[n-1] += c
				break
			}
			for LatencyBoundsMs[j] < legacyBoundsMs[i] {
				j++
			}
			out[j] += c
		}
		return out
	default:
		out := make([]int64, n)
		copy(out, b)
		return out
	}
}

// BucketTotal — число наблюдений в гистограмме (для оценки достоверности p95).
func BucketTotal(b []int64) int64 {
	var t int64
	for _, c := range b {
		t += c
	}
	return t
}

func bucketIndex(latency time.Duration) int {
	ms := float64(latency) / float64(time.Millisecond)
	for i, b := range LatencyBoundsMs {
		if ms <= b {
			return i
		}
	}
	return len(LatencyBoundsMs)
}

// Quantile — квантиль q (0..1) по гистограмме с линейной интерполяцией внутри бакета.
// Для переполняющего бакета возвращает последнюю границу.
func Quantile(buckets []int64, q float64) float64 {
	buckets = NormalizeBuckets(buckets)
	var total int64
	for _, c := range buckets {
		total += c
	}
	if total == 0 {
		return 0
	}
	target := q * float64(total)
	var cum int64
	for i, c := range buckets {
		if c == 0 {
			continue
		}
		if float64(cum+c) < target {
			cum += c
			continue
		}
		if i >= len(LatencyBoundsMs) {
			return LatencyBoundsMs[len(LatencyBoundsMs)-1]
		}
		lo := 0.0
		if i > 0 {
			lo = LatencyBoundsMs[i-1]
		}
		hi := LatencyBoundsMs[i]
		return lo + (hi-lo)*(target-float64(cum))/float64(c)
	}
	return LatencyBoundsMs[len(LatencyBoundsMs)-1]
}

// P95 — 95-й перцентиль по гистограмме, мс.
func P95(buckets []int64) float64 { return Quantile(buckets, 0.95) }

func addBuckets(dst, src []int64) []int64 {
	src = NormalizeBuckets(src)
	if len(src) > len(dst) {
		dst = append(dst, make([]int64, len(src)-len(dst))...)
	}
	for i, c := range src {
		dst[i] += c
	}
	return dst
}

func addDenied(dst, src map[string]int64) map[string]int64 {
	if len(src) == 0 {
		return dst
	}
	if dst == nil {
		dst = make(map[string]int64, len(src))
	}
	for k, v := range src {
		dst[k] += v
	}
	return dst
}
