// Package mtproto — серверная часть MTProto-прокси tgproxy (docs/mtproto.md).
//
// Пакет закрывает github.com/9seconds/mtg/v2 (pin v2.2.8) тонким адаптером:
// Manager держит по инстансу mtglib.Proxy на секрет, Network реализуется через
// агентов, FakeTLS-разводка и лимиты делаются до передачи соединения в mtg.
//
// Файл mtgcontract_test.go фиксирует поведение mtg, на которое опирается дизайн.
// При обновлении mtg эти тесты падают первыми; расхождение с docs/mtproto.md
// считается ошибкой дизайна, а не теста.
package mtproto
