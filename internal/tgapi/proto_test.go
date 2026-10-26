package tgapi

import "testing"

func TestPhaseNotSent(t *testing.T) {
	for _, p := range []string{PhaseDial, PhaseTLS, PhasePreSend} {
		if !PhaseNotSent(p) {
			t.Errorf("%s: want not sent", p)
		}
	}
	for _, p := range []string{PhaseWrite, PhaseRead, PhaseTimeout, "", "x"} {
		if PhaseNotSent(p) {
			t.Errorf("%q: want maybe sent", p)
		}
	}
}
