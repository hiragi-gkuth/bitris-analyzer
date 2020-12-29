// Package net は，ネットワークプロトコルに関する機能を提供する
package net

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

// IP express the IPv4 structure
type IP struct {
	Octets [4]uint64
}

// NewDefaultIP return default IP struct
func NewDefaultIP() IP {
	return IP{
		[4]uint64{0, 0, 0, 0},
	}
}

// NewIPFromString return IP struct by string
func NewIPFromString(ipStr string) IP {
	stringOctets := strings.Split(ipStr, ".")
	if len(stringOctets) != 4 {
		panic("invalid ip string")
	}

	octets := [4]uint64{}
	for i, stringOctet := range stringOctets {
		var e error
		octets[i], e = strconv.ParseUint(stringOctet, 10, 8)
		if e != nil {
			panic(e.Error())
		}
	}
	return IP{octets}
}

func (ip IP) String() string {
	return fmt.Sprintf("%v.%v.%v.%v", ip.Octets[0], ip.Octets[1], ip.Octets[2], ip.Octets[3])
}

// SubnetMask return IP Address masked by subnet mask
func (ip IP) SubnetMask(mask int) IP {
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

	return IP{
		Octets: subnetOctets,
	}
}

// Equal method for go-cmp
func (ip IP) Equal(cmp IP) bool {
	for i := 0; i < 4; i++ {
		if ip.Octets[i] != cmp.Octets[i] {
			return false
		}
	}
	return true
}
