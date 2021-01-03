package main

import (
	"fmt"
	"log"
	"time"

	"github.com/hiragi-gkuth/bitris-analyzer/internal/simulator"
)

func main() {
	begin, e := time.Parse("2006-01-02 15:04:05", "2020-11-04 00:00:00")

	if e != nil {
		log.Fatal(e)
	}
	sim := simulator.New("uehara")

	sim.SetSimulateType(simulator.Legacy | simulator.TimeSummarized | simulator.IPSummarized)
	sim.SetSubnetMask(16)
	sim.SetVerbose(true)
	sim.SetWithRTT(true)
	sim.SetTerm(begin, 0, 24*14*time.Hour)
	sim.Prefetch()

	results := []simulator.Results{}
	for i := 0; i < 10; i++ {
		begin = begin.Add(24 * time.Hour)
		sim.SetTerm(begin, 24*time.Hour, 24*time.Hour)

		results = append(results, sim.Simulate())
	}

	legacyPerfs := 0.0
	timePerfs := 0.0
	ipPerfs := 0.0
	for _, r := range results {
		legacyPerfs += r.Of[simulator.Legacy].Performance
		timePerfs += r.Of[simulator.TimeSummarized].Performance
		ipPerfs += r.Of[simulator.IPSummarized].Performance
	}
	fmt.Println(legacyPerfs)
	fmt.Println(timePerfs)
	fmt.Println(ipPerfs)
}
