package authinfo

import (
	"time"
)

// AuthData is structure of manipulate
type AuthData struct {
	ID             int
	User           string
	IP             IPAddr
	Success        bool
	Attack         bool
	Authtime       float64
	ActualAuthtime float64
	RTT            float64
	AuthAt         time.Time
}
