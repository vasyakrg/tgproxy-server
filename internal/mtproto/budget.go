package mtproto

import "fmt"

// fdReserve — fd, оставляемые под Bot API и служебные нужды (docs/mtproto.md §9).
const fdReserve = 16384

// fdBudgetCheck возвращает текст предупреждения, если max_conns×2 + резерв
// превышает лимит дескрипторов; пустая строка — бюджет в порядке.
func fdBudgetCheck(maxConns int, limit uint64) string {
	need := uint64(max(maxConns, 0))*2 + fdReserve //nolint:gosec // значение неотрицательно
	if need <= limit {
		return ""
	}
	return fmt.Sprintf(
		"mtproto: fd-бюджет не хватает: max_conns×2 + %d = %d, RLIMIT_NOFILE = %d; увеличьте LimitNOFILE или уменьшите mtproto.max_conns",
		fdReserve, need, limit)
}

// CheckFDBudget сверяет mtproto.max_conns с RLIMIT_NOFILE процесса и
// возвращает предупреждение для лога (пусто — всё в порядке или лимит неизвестен).
func CheckFDBudget(maxConns int) string {
	limit, ok := nofileLimit()
	if !ok {
		return ""
	}
	return fdBudgetCheck(maxConns, limit)
}
