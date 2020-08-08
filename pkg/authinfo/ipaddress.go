package authinfo

import (
	"fmt"
	"math"
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

// SubnetMask return IP Address masked by subnet mask
func (ip IPAddr) SubnetMask(mask int) IPAddr {
	if mask < 0 || mask > 32 {
		panic("Subnet mask must be in 0< and >32")
	}
	raw := uint32(ip.Octets[0]<<24 | ip.Octets[1]<<16 | ip.Octets[2]<<8 | ip.Octets[3])
	rawMask := uint32(math.Pow(2, float64(mask))-1) << (32 - mask)
	rawSubnet := raw & rawMask

	var subnetOctets [4]uint64
	for octet := 0; octet < 4; octet++ {
		bit := octet * 8
		subnetOctets[octet] = uint64(rawSubnet << bit >> 24)
	}

	return IPAddr{
		Octets: subnetOctets,
	}
}
