package mtproto

import (
	"testing"

	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	// пулы горутин mtglib (ants) живут до конца процесса
	goleak.VerifyTestMain(m,
		goleak.IgnoreAnyFunction("github.com/panjf2000/ants/v2.(*poolCommon).goPurge"),
		goleak.IgnoreAnyFunction("github.com/panjf2000/ants/v2.(*poolCommon).purgeStaleWorkers"),
		goleak.IgnoreAnyFunction("github.com/panjf2000/ants/v2.(*poolCommon).ticktock"),
	)
}
