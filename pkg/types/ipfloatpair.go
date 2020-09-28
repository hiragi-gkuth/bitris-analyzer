package types

import (
	"sort"

	"github.com/hiragi-gkuth/bitris-analyzer/pkg/net"
)

// IPFloatPair is
type IPFloatPair struct {
	key   net.IP
	value float64
}

// IPFloatPairList is list of IPFloatPair
type IPFloatPairList []*IPFloatPair

// Sort return new slices of IpFLoatPairList
func (ifpl IPFloatPairList) Sort() (result IPFloatPairList) {
	result = make(IPFloatPairList, len(ifpl))
	copy(ifpl, result)
	sort.Slice(result, func(i, j int) bool { return ifpl[i].value < ifpl[j].value })

	return result
}

// Add adding value on IP
func (ifpl IPFloatPairList) Add(key net.IP, value float64) {
	newPair := IPFloatPair{
		key:   key,
		value: 1,
	}
	ifpl = append(ifpl, &newPair)
}
