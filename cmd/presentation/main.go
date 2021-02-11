package main

import (
	"fmt"
	"time"

	"github.com/hiragi-gkuth/bitris-analyzer/internal/simulator"
)

func main() {
	format := "2006-01-02 15:04:05"
	beginStr := "2020-11-04 00:00:00"

	begin, _ := time.Parse(format, beginStr)
	end := begin.Add(20 * 24 * time.Hour)

	s := simulator.New("uehara", "cririn")

	s.SetSimulateType(simulator.Legacy | simulator.IPTimeSummarized)
	s.SetWithRTT(true)
	// s.SetVerbose(true)
	s.SetSlotInterval(24*time.Hour, 24)
	s.SuperPrefetch(begin, end)

	for b := begin; b.Before(end); b = b.Add(24 * time.Hour) {
		s.SetTerm(b, 24*time.Hour, 24*time.Hour)
		results := s.Simulate()

		leg := results.Of[simulator.Legacy]
		shi := results.Of[simulator.IPTimeSummarized]

		fmt.Printf("%s,%f,%f,%f,%f,%f,%f\n", b.Format(format), leg.DetectionRate, leg.MisDetectionRate, leg.Performance, shi.DetectionRate, shi.MisDetectionRate, shi.Performance)
	}
}
