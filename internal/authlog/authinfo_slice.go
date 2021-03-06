// Generated by: gen
// TypeWriter: slice
// Directive: +gen on *authlog

package authlog

import (
	"math"
	"fmt"
	"sort"
)

// AuthInfoSlice is a slice of type *authlog. Use it where you would use []*AuthInfo.
type AuthInfoSlice []*AuthInfo

// Where returns a new AuthInfoSlice whose elements return true for func. See: http://clipperhouse.github.io/gen/#Where
func (rcv AuthInfoSlice) Where(fn func(*AuthInfo) bool) (result AuthInfoSlice) {
	for _, v := range rcv {
		if fn(v) {
			result = append(result, v)
		}
	}
	return result
}

// Max returns max data based on fn
func (rcv AuthInfoSlice) Max(fn func(*AuthInfo) float64) AuthInfo {
	sort.Slice(rcv, func(i, j int) bool { return fn(rcv[i]) < fn(rcv[j]) })
	return *rcv[0]
}

// Min returns min data based on fn
func (rcv AuthInfoSlice) Min(fn func(*AuthInfo) float64) AuthInfo {
	sort.Slice(rcv, func(i, j int) bool { return fn(rcv[i]) > fn(rcv[j]) })
	return *rcv[0]
}

// Percentile returns quantiled element based on q param
func (rcv AuthInfoSlice) Percentile(p float64, fn func(*AuthInfo) float64) (int, AuthInfo) {
	// sorting slice min - max order
	sort.Slice(rcv, func(i ,j int) bool { return fn(rcv[i]) > fn(rcv[j]) })
	pos := int(math.Round(float64(len(rcv)) * p))
	return pos, *rcv[pos]
}

// ShowInfo shows data list like sql
func (rcv AuthInfoSlice) ShowInfo() {
	fmt.Printf("ID\t\tUser\t\tPassword\tIP\t\tGeo\tAuthtime\tRTT\tAuthAt\n")
	for _, ad := range rcv {
		fmt.Printf("%09d\t%-12s\t%-12s\t%s\t%s\t%.3f\t\t%.3f\t%s\n", ad.ID, ad.User, ad.Password, ad.IP.String(), ad.GeoInfo.Country_short, ad.ActualAuthtime, ad.RTT, ad.AuthAt.String())
	}
}
