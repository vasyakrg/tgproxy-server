package agent

// ReverseConns — число живых reverse-соединений агента с сервером (0 вне
// режимов reverse/both). Для метрики tgp_agent_reverse_conns.
func (a *Agent) ReverseConns() int {
	_, _, conns, _ := a.mgr.snapshot()
	return conns
}
