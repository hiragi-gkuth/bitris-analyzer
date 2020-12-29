package simulator

import "github.com/hiragi-gkuth/bitris-analyzer/pkg/authlog"

func (s Simulator) selectAuthtime(auth *authlog.AuthInfo) float64 {
	if s.withRTT {
		return auth.Authtime
	}
	return auth.ActualAuthtime
}
