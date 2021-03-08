// Package threshold は，しきい値データの操作機能を提供する
package threshold

import (
	"fmt"
	"net"
	"time"
)

// Threshold is analyzed thresholds per IP, Time and so on
type Threshold struct {
	BaseThreshold float64
	OnIP          *OnIP
	OnTime        *OnTime
	OnIPTime      *OnIPTime
}

// New return new one
func New(subnetMask int, entireDuration time.Duration, divisions int) *Threshold {
	return &Threshold{
		BaseThreshold: 0.0,
		OnIP:          NewOnIP(subnetMask),
		OnTime:        NewOnTime(entireDuration, divisions),
		OnIPTime:      NewOnIPTime(subnetMask, entireDuration, divisions),
	}
}

// Show shows calculation result
func (rcv *Threshold) Show() {
	fmt.Printf("Base: %.3f\n", rcv.BaseThreshold)

	fmt.Println("OnTime:")

	for t, threshold := range rcv.OnTime.m {
		fmt.Printf("  %v ->\t %.3f\n", time.Duration(t)*time.Second, threshold)
	}

	fmt.Println("OnIPTime:")
	for ipStr, threshold := range rcv.OnIPTime.onIP.List() {
		ip := net.ParseIP(ipStr)
		fmt.Printf("  %s ->\t %.3f\n", ip.String(), threshold)
		onTime, _ := rcv.OnIPTime.GetByIP(ip)
		for t, thresholdForTime := range onTime.m {
			fmt.Printf("    %v ->\t %.3f\n", time.Duration(t*int64(time.Second)), thresholdForTime)
		}
	}
}
