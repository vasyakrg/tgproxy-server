package agent

// ReverseConns — число живых reverse-соединений агента с сервером (0 вне
// режимов reverse/both). Для метрики tgp_agent_reverse_conns.
func (a *Agent) ReverseConns() int {
	_, _, conns, _ := a.mgr.snapshot()
	return conns
}

// MTProtoReverseConns — живые соединения MTProto-класса и целевой размер пула
// (0, 0 вне reverse/both или при mtproto.enabled=false).
func (a *Agent) MTProtoReverseConns() (conns, target int) { return a.mgr.mtprotoConns() }
