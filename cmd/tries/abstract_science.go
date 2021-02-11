package main

import (
	"fmt"
	"time"

	"github.com/hiragi-gkuth/bitris-analyzer/internal/simulator"
)

func main() {
	abstractScience()
}

func abstractScience() {
	begin, _ := time.Parse("2006-01-02 15:04:05", "2020-11-04 00:00:00")
	end := begin.Add(24 * 21 * time.Hour)

	sim := simulator.New("uehara", "cririn")

	sim.SetSimulateType(simulator.Legacy | simulator.TimeSummarized | simulator.IPSummarized | simulator.IPTimeSummarized)
	sim.SetSubnetMask(24)
	sim.SetSlotInterval(24*time.Hour, 24)
	sim.SetVerbose(false)
	sim.SetWithRTT(true)

	sim.SuperPrefetch(begin, end)

	content := "\n"

	content += fmt.Sprintf("date,base,legDetec,legMiss,newDetec,newMiss\n")

	for i := 0; i <= 20; i++ {
		aPeriod := 24 * time.Hour
		oPeriod := 24 * time.Hour
		b := begin.Add(time.Duration(i) * 24 * time.Hour)

		sim.SetTerm(b, aPeriod, oPeriod)
		results := sim.Simulate()

		l := results.Of[simulator.Legacy]
		n := results.Of[simulator.IPTimeSummarized]

		content += fmt.Sprintf("%s,%f,%f,%f,%f\n", b.Format("2006-01-02 15:04:05"),
			l.DetectionRate, l.MisDetectionRate, n.DetectionRate, n.MisDetectionRate)
	}

	fmt.Println(content)
}
