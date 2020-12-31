package analyze

import (
	"fmt"
	"log"
	"net"
)

// OnIP is per IP threshold map, m's key is IP string like "10.1.16.0/24" or "::0/8"
type OnIP struct {
	mask int
	m    map[string]float64
}

// Set sets threshold
func (o *OnIP) Set(ipStr string, threshold float64) {
	_, ipnet, e := net.ParseCIDR(fmt.Sprintf("%s/%d", ipStr, o.mask))
	if e != nil {
		log.Print("failed to set OnIP due to invalid IP String", ipStr)
		return
	}
	o.m[ipnet.String()] = threshold
}

// Get gets threshold from ipStr
// func (o *OnIP) Get(ipStr string) (float64, bool) {
// 	ip := net.ParseIP(ipStr)
// 	subnet := ip.Mask(o.mask)
// 	threshold, ok := o.m[subnet.String()]

// 	return threshold, ok
// }

// Get gets threshold from ip
func (o *OnIP) Get(ip net.IP) (float64, bool) {
	_, ipnet, e := net.ParseCIDR(fmt.Sprintf("%s/%d", ip.String(), o.mask))
	if e != nil {
		log.Print("failed to get OnIP due to invalid ip")
		return 0.0, false
	}
	threshold, ok := o.m[ipnet.String()]

	return threshold, ok
}

// NewOnIP returns new one
func NewOnIP(subnetMask int) *OnIP {
	return &OnIP{
		mask: subnetMask,
		m:    make(map[string]float64),
	}
}
