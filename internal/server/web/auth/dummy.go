package auth

import "sync"

var (
	dummyOnce sync.Once
	dummyHash string
)

// dummyPHC — фиктивный хеш с параметрами по умолчанию (генерируется один раз).
func dummyPHC() string {
	dummyOnce.Do(func() {
		h, err := Hash("tgproxy-dummy-password", DefaultHashParams())
		if err != nil { // недостижимо: параметры константны
			panic(err)
		}
		dummyHash = h
	})
	return dummyHash
}

// VerifyDummy тратит столько же времени, сколько реальная проверка пароля;
// вызывается для несуществующих/отключённых/некорректных пользователей. Всегда false.
func VerifyDummy(password string) bool {
	Verify(password, dummyPHC())
	return false
}
