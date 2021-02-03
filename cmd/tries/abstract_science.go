package main

import (
	"fmt"
	"time"

	"github.com/hiragi-gkuth/bitris-analyzer/internal/simulator"
)

func abstractScience() {
	begin, _ := time.Parse("2006-01-02 15:04:05", "2020-11-04 00:00:00")
	end := begin.Add(24 * 21 * time.Hour)

	sim := simulator.New("uehara", "cririn")

	sim.SetSimulateType(simulator.Legacy | simulator.TimeSummarized | simulator.IPSummarized | simulator.IPTimeSummarized)
	sim.SetSubnetMask(24)
	sim.SetSlotInterval(24*time.Hour, 24)
	sim.SetVerbose(true)
	sim.SetWithRTT(true)

	sim.SuperPrefetch(begin, end)

	baseThresholds := []float64{}
	legacyDetecs := []float64{}
	timeDetecs := []float64{}
	ipDetecs := []float64{}
	ipTimeDetecs := []float64{}
	hitRates := []float64{}

	for i := 0; i < 20; i++ {
		aPeriod := 24 * time.Hour
		oPeriod := 24 * time.Hour
		b := begin.Add(time.Duration(i) * 24 * time.Hour)

		sim.SetTerm(b, aPeriod, oPeriod)
		results := sim.Simulate()

		baseThresholds = append(baseThresholds, results.Of[simulator.Legacy].BaseThreshold)
		legacyDetecs = append(legacyDetecs, results.Of[simulator.Legacy].DetectionRate)
		ipTimeDetecs = append(ipTimeDetecs, results.Of[simulator.IPTimeSummarized].DetectionRate)
		ipDetecs = append(ipDetecs, results.Of[simulator.IPSummarized].DetectionRate)
		timeDetecs = append(timeDetecs, results.Of[simulator.TimeSummarized].DetectionRate)
		hitRates = append(hitRates, results.Of[simulator.IPSummarized].HitRate)
	}

	fmt.Printf("base,legacy,ip,time,ip-time,hitrate\n")
	// 集計
	for i := 0; i < 20; i++ {
		fmt.Printf("%v,%v,%v,%v,%v,%v\n", baseThresholds[i], legacyDetecs[i], ipDetecs[i], timeDetecs[i], ipTimeDetecs[i], hitRates[i])
	}
}
