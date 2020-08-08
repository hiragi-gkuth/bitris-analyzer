package authinfo

import (
	"strconv"
	"time"
)

// AuthData is structure of manipulate
type AuthData struct {
	ID             int
	User           string
	Password       string
	IP             IPAddr
	Success        bool
	Attack         bool
	Authtime       float64
	ActualAuthtime float64
	RTT            float64
	AuthAt         time.Time
}

// ToLoggable is converter for fluent logging
func (a AuthData) ToLoggable() map[string]string {
	return map[string]string{
		"LoggedID": strconv.Itoa(a.ID),
		"User":     a.User,
		"IP":       a.IP.String(),
	}
}
