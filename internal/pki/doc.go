// Package pki — встроенный CA и mTLS-хелперы tgproxy (dev-уровень).
//
// Идентичность задаётся URI SAN: сервер — spiffe://tgproxy/server,
// агент — spiffe://tgproxy/agent/<id>. CN/SAN из CSR никогда не доверяются.
// KEK-шифрование ключа CA, ротация и denylist серийников — M5; точки
// расширения: [LoadCA] принимает уже расшифрованный PEM, [Check] подключается
// к Verify*Peer (denylist).
package pki
