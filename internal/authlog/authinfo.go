// Package authlog provide structure and funcs for authlog
package authlog

import (
	"time"

	"github.com/ip2location/ip2location-go"

	"github.com/hiragi-gkuth/bitris-analyzer/internal/net"
)

// AuthInfo is structure of manipulate
// +gen * slice:"Where"
type AuthInfo struct {
	ID             int
	User           string
	Password       string
	IP             net.IP
	GeoInfo        ip2location.IP2Locationrecord
	Success        bool
	Authtime       float64
	ActualAuthtime float64
	RTT            float64
	AuthAt         time.Time
}
