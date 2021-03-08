package threshold

import (
	"fmt"
	"log"
	"net"
	"time"
)

// OnIPTime is per IP-Time threshold map, m's key is IP string like "10.1.16.0/24" or "::0/8"
type OnIPTime struct {
	entireDuration time.Duration
	divisions      int
	mask           int
	onIP           *OnIP
	m              map[string]*OnTime
}

// NewOnIPTime returns new one
func NewOnIPTime(subnetMask int, entireDuration time.Duration, divisions int) *OnIPTime {
	return &OnIPTime{
		mask:           subnetMask,
		entireDuration: entireDuration,
		divisions:      divisions,
		onIP:           NewOnIP(subnetMask),
		m:              make(map[string]*OnTime),
	}
}

// SetForIP は，IP-Timeのうち，IPへのしきい値を設定する
func (rcv *OnIPTime) SetForIP(ipStr string, threshold float64) {
	_, ipnet, e := net.ParseCIDR(fmt.Sprintf("%s/%d", ipStr, rcv.onIP.mask))
	if e != nil {
		log.Print("failed to set OnIP due to invalid IP String", ipStr)
		return
	}
	rcv.onIP.m[ipnet.String()] = threshold
}

// SetForIPTime は，IP-Timeのうち，あるIPアドレスのある時間帯へのしきい値を設定する
func (rcv *OnIPTime) SetForIPTime(ipStr string, t time.Time, threshold float64) {
	_, ipnet, e := net.ParseCIDR(fmt.Sprintf("%s/%d", ipStr, rcv.onIP.mask))
	if e != nil {
		log.Print("failed to set OnIP due to invalid IP String", ipStr)
		return
	}

	if m, ok := rcv.m[ipnet.String()]; !ok {
		m = NewOnTime(rcv.entireDuration, rcv.divisions)
		m.Set(t, threshold)
		rcv.m[ipnet.String()] = m
	} else {
		m.Set(t, threshold)
		rcv.m[ipnet.String()] = m
	}
}

// GetByIP は，指定されたIPに対する時間ごとしきい値を返す
func (rcv OnIPTime) GetByIP(ip net.IP) (*OnTime, bool) {
	_, ipnet, e := net.ParseCIDR(fmt.Sprintf("%s/%d", ip.String(), rcv.onIP.mask))
	if e != nil {
		log.Print("failed to get OnIP due to invalid ip")
		return nil, false
	}
	onTime, ok := rcv.m[ipnet.String()]
	return onTime, ok
}
