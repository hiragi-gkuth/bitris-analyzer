package authinfo

import (
	"fmt"
	"strconv"
	"strings"
)

// IPAddr express the IPv4 structure
type IPAddr struct {
	Octets [4]uint64
}

func (ip IPAddr) String() string {
	return fmt.Sprintf("%v.%v.%v.%v", ip.Octets[0], ip.Octets[1], ip.Octets[2], ip.Octets[3])
}

// FromString makes IPAddr structure from string like "255.255.255.0"
func (ip *IPAddr) FromString(ipStr string) {
	ipOctets := strings.Split(ipStr, ".")
	if len(ipOctets) != 4 {
		panic("invalid ip string")
	}
	for i, ipOctet := range ipOctets {
		var e error
		ip.Octets[i], e = strconv.ParseUint(ipOctet, 10, 8)
		if e != nil {
			panic(e.Error())
		}
	}
}
