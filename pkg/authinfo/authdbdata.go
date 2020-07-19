package authinfo

import (
	"fmt"
	"strconv"
	"time"
)

// AuthDbData express raw tables
type AuthDbData struct {
	ID       string
	Result   string
	User     string
	IP       string
	Authtime float64
	Detect   string
	RTT      float64
	Year     string
	Month    string
	Day      string
	Hour     string
	Minute   string
	Second   string
	Usecond  string
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
		Success:        (add.Result == "Success"),
		Attack:         (add.Detect == "Attack"),
		Authtime:       add.Authtime,
		ActualAuthtime: (add.Authtime - add.RTT),
		RTT:            add.RTT,
		AuthAt:         toTime(add.Year, add.Month, add.Day, add.Hour, add.Minute, add.Second, add.Usecond),
		IP:             toIPAddr(add.IP),
	}

	return ad
}

func toTime(year string, month string, day string, hour string, minute string, second string, usecond string) time.Time {
	datetimeString := fmt.Sprintf("%v/%v/%v %v:%v:%v.%v", year, month, day, hour, minute, second, usecond)
	t, e := time.ParseInLocation("2006/01/02 15:04:05.000000", datetimeString, time.UTC)
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
