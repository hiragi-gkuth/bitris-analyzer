// Package summarizer は，認証情報を様々な要素によって分類，要約する機能を提供する
package summarizer

import (
	"github.com/hiragi-gkuth/bitris-analyzer/internal/authlog"
	"github.com/hiragi-gkuth/bitris-analyzer/internal/net"
)

// ByIPSummary は，IPアドレスごとにまとめられた認証情報を示す
type ByIPSummary struct {
	IP         net.IP
	Auths      authlog.AuthInfoSlice
	Percentage float64
}

// ByIPSummarySlice は，ByIPSummaryのスライス
type ByIPSummarySlice []*ByIPSummary

// ByIPSummaryMap は，ByIPSummaryのマップ
type ByIPSummaryMap map[net.IP]*ByIPSummary

// ByIP は，引数に与えられた認証情報のスライスを，サブネット単位のネットワークアドレスごとに分類して返す
func ByIP(auths authlog.AuthInfoSlice, subnetMask int) ByIPSummarySlice {
	// summarying
	summaryMap := ByIPSummaryMap{}

	for _, auth := range auths {
		subnet := auth.IP.SubnetMask(subnetMask)
		if summary, ok := summaryMap[subnet]; ok {
			summary.Auths = append(summary.Auths, auth)
		} else {
			summaryMap[subnet] = &ByIPSummary{
				IP:         subnet,
				Auths:      authlog.AuthInfoSlice{auth},
				Percentage: 0.0,
			}
		}
	}

	// convert to Slice
	summarySlice := ByIPSummarySlice{}
	entireLen := len(auths)
	for _, summary := range summaryMap {
		summary.Percentage = float64(len(summary.Auths)) / float64(entireLen)
		summarySlice = append(summarySlice, summary)
	}
	return summarySlice
}
