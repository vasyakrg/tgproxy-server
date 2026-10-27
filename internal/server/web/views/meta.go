package views

// Ключи разделов сайдбара (PageMeta.Active).
const (
	NavOverview = "overview"
	NavAgents   = "agents"
	NavAccess   = "access"
	NavBans     = "bans"
	NavMTProto  = "mtproto"
	NavErrors   = "errors"
	NavSystem   = "system"
)

// PageMeta — данные страницы для Layout.
type PageMeta struct {
	Title   string // заголовок вкладки (без суффикса « — tgproxy»)
	Active  string // один из Nav*; пусто — ни один пункт не активен
	Version string // версия сервера в сайдбаре
	User    string // логин для блока «Выйти»
	CSRF    string // CSRF-токен для формы /logout; пусто — поле не выводится
}

type navItem struct {
	Key, Href, Label, Icon string
}

var navItems = []navItem{
	{NavOverview, "/", "Обзор", "pulse"},
	{NavAgents, "/agents", "Агенты", "servers"},
	{NavAccess, "/access", "Доступ", "shield"},
	{NavBans, "/bans", "Баны", "ban"},
	{NavMTProto, "/mtproto", "MTProto", "send"},
	{NavErrors, "/errors", "Ошибки", "alert"},
	{NavSystem, "/system", "Система", "gear"},
}

func ariaCurrent(active, key string) string {
	if active == key {
		return "page"
	}
	return "false"
}
