package tgapi

// Внутренний контракт server ↔ agent (docs/architecture.md §4).

// AgentTGPrefix — префикс прокси-эндпоинта агента: /tg/<Route.UpstreamPath()>.
const AgentTGPrefix = "/tg/"

// Заголовки запроса server → agent.
const (
	HeaderRequestID = "X-Request-ID"
	HeaderTimeoutMs = "X-TGP-Timeout-Ms" // относительный дедлайн, мс
	HeaderAttempt   = "X-TGP-Attempt"
	HeaderBotID     = "X-TGP-Bot-ID"
	HeaderProxyKey  = "X-Proxy-Key" // клиент → server, альтернатива /k/<key>
)

// Заголовки ответа agent → server.
const (
	HeaderSource     = "X-TGP-Source"      // SourceTelegram | SourceAgent
	HeaderErrorPhase = "X-TGP-Error-Phase" // Phase*
	HeaderUpstreamMs = "X-TGP-Upstream-Ms"
)

// Значения HeaderSource: ответ сформировал Telegram или сам агент.
const (
	SourceTelegram = "telegram"
	SourceAgent    = "agent"
)

// Фазы отказа. До PhasePreSend включительно запрос гарантированно не ушёл
// в Telegram — ретрай unsafe-методов допустим только для них.
const (
	PhaseDial    = "dial"
	PhaseTLS     = "tls"
	PhasePreSend = "pre-send"
	PhaseWrite   = "write"
	PhaseRead    = "read"
	PhaseTimeout = "timeout"
)

// PhaseNotSent сообщает, что при такой фазе запрос точно не дошёл до Telegram.
func PhaseNotSent(phase string) bool {
	switch phase {
	case PhaseDial, PhaseTLS, PhasePreSend:
		return true
	}
	return false
}
