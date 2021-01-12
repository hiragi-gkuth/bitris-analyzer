// Package summarizer は，認証情報を様々な要素によって分類，要約する機能を提供する
package summarizer

import (
	"fmt"
	"time"

	"github.com/hiragi-gkuth/bitris-analyzer/internal/authlog"
)

// ByTimeSummary は，IPアドレスごとにまとめられた認証情報を示す
type ByTimeSummary struct {
	Slot       ITimeSlot
	Auths      authlog.AuthInfoSlice
	Percentage float64
}

// ByTimeSummarySlice は，ByTimeSummaryのスライス
type ByTimeSummarySlice []*ByTimeSummary

// ByTimeSummaryMap は，ByTimeSummaryのマップ
type ByTimeSummaryMap map[string]*ByTimeSummary

// ByTime は，引数に与えられた認証情報のスライスを，interval単位内で，divisions分割した要約を返す
func ByTime(auths authlog.AuthInfoSlice, interval time.Duration, divisions int) ByTimeSummarySlice {
	// summarying
	summarySlice := ByTimeSummarySlice{}

	for slot := NewTimeSlot(interval, divisions); slot.DuringInterval(); slot = slot.Next() {
		inSlotAuths := auths.Where(func(auth *authlog.AuthInfo) bool {
			return slot.IsInSlot(auth.AuthAt)
		})
		summary := ByTimeSummary{
			Slot:       slot,
			Auths:      inSlotAuths,
			Percentage: 0.0,
		}
		summarySlice = append(summarySlice, &summary)
	}
	return summarySlice
}

// Key returns map key to construct TimeThreshold map
func (vts ByTimeSummary) Key() string {
	return fmt.Sprintf("%v", vts.Slot.Begin())
}

// ToMap convert ByTimeSummarySlice to Map
func (btss ByTimeSummarySlice) ToMap() ByTimeSummaryMap {
	m := make(ByTimeSummaryMap)
	for _, summ := range btss {
		m[summ.Key()] = summ
	}
	return m
}

// ToSlice convert ByTimeSummaryMap to Slice
func (btsm ByTimeSummaryMap) ToSlice() ByTimeSummarySlice {
	s := make(ByTimeSummarySlice, 0)
	for _, summ := range btsm {
		s = append(s, summ)
	}
	return s
}

// GetKeyFromAuthAt is
func GetKeyFromAuthAt(authAt time.Time, interval time.Duration, divisions int) string {
	for slot := NewTimeSlot(interval, divisions); slot.DuringInterval(); slot = slot.Next() {
		if slot.IsInSlot(authAt) {
			return fmt.Sprintf("%v", slot.Begin())
		}
	}
	return ""
}
