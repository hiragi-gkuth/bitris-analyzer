package authlog

import (
	"encoding/hex"
	"strconv"
	"time"
	"unsafe"

	"github.com/ip2location/ip2location-go"

	"github.com/hiragi-gkuth/bitris-analyzer/internal/net"
)

// AuthRawInfo express raw tables
type AuthRawInfo struct {
	ID       string
	Result   string
	User     string
	Password string
	IP       string
	Authtime float64
	Detect   string
	RTT      float64
	Unixtime int64
	Usec     int64
	Kex      float64
	NewKey   float64
}

// NewAuthRawInfo returns empty structure
func NewAuthRawInfo() AuthRawInfo {
	return AuthRawInfo{}
}

// GeoInfo express posision
type GeoInfo struct {
	code string
	lat  float64
	long float64
}

// ConvertToAuthInfo is converter
func (add AuthRawInfo) ConvertToAuthInfo(geoDB *ip2location.DB) *AuthInfo {
	intID, _ := strconv.Atoi(add.ID)

	//24 ごとでチョットやってみる
	ip := net.NewIPFromString(add.IP) //.SubnetMask(16)
	geoResult, err := geoDB.Get_all(ip.String())
	if err != nil {
		panic(err.Error())
	}

	ad := AuthInfo{
		ID:             intID,
		User:           hex2Ascii(add.User),
		Password:       hex2Ascii(add.Password),
		IP:             ip,
		GeoInfo:        geoResult,
		Success:        (add.Result == "Success"),
		Authtime:       add.Authtime,
		ActualAuthtime: (add.Authtime - add.RTT),
		RTT:            add.RTT,
		AuthAt:         time.Unix(add.Unixtime, add.Usec*1000),
	}
	return &ad
}

func hex2Ascii(hexString string) string {
	decoded, e := hex.DecodeString(hexString)
	if e != nil {
		panic(e.Error() + hexString)
	}
	return *(*string)(unsafe.Pointer(&decoded))
}
