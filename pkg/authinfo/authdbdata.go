package authinfo

import (
	"strconv"
	"time"
)

// AuthDbData express raw tables
type AuthDbData struct {
	ID       string
	Result   string
	User     string
	Password string
	IP       string
	Authtime float64
	Detect   string
	RTT      float64
	AuthAt   string
	Kex      float64
	NewKey   float64
}

// NewAuthDbData returns empty structure
func NewAuthDbData() AuthDbData {
	return AuthDbData{}
}

// ConvertToAuthData is converter
func (add AuthDbData) ConvertToAuthData() AuthData {
	intID, _ := strconv.Atoi(add.ID)
	ad := AuthData{
		ID:             intID,
		User:           add.User,
		Password:       add.Password,
		IP:             toIPAddr(add.IP),
		Success:        (add.Result == "Success"),
		Attack:         (add.Detect == "Attack"),
		Authtime:       add.Authtime,
		ActualAuthtime: (add.Authtime - add.RTT),
		RTT:            add.RTT,
		AuthAt:         toTime(add.AuthAt),
	}

	return ad
}

func toTime(datetimeString string) time.Time {
	t, e := time.ParseInLocation("2006-01-02 15:04:05", datetimeString, time.UTC)
	if e != nil {
		panic(e)
	}
	return t
}

func toIPAddr(ipAddrString string) IPAddr {
	var ip IPAddr
	ip.FromString(ipAddrString)
	return ip
}
