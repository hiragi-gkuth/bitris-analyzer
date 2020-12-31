package main

import "github.com/hiragi-gkuth/bitris-analyzer/internal/authlog"

func topIPsFilter(a *authlog.AuthInfo) bool {
	subnet := a.IP.SubnetMask(16).String()
	topIPs := []string{
		"49.88.0.0",
		"112.85.0.0",
		"122.85.0.0",
		"61.117.0.0",
	}
	for _, ip := range topIPs {
		if subnet == ip {
			return false
		}
	}
	return true
}

func noFilter(a *authlog.AuthInfo) bool {
	return true
}
