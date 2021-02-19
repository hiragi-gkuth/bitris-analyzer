package main

import (
	"fmt"
	"io/ioutil"
	"time"

	"github.com/hiragi-gkuth/bitris-analyzer/internal/simulator"
)

func examine(ap time.Duration, ops []time.Duration) {
	begin, _ := time.Parse(Format, Begin)
	end := begin.Add(31 * 24 * time.Hour)

	// operationPeriods := func() []time.Duration {
	// 	ops := []time.Duration{}
	// 	for i := 1; i <= 96; i++ {
	// 		ops = append(ops, time.Duration(i)*time.Hour)
	// 	}
	// 	return ops
	// }()

	operationPeriods := ops

	// setup Simulator
	sim := simulator.New("uehara", "uehara")
	sim.SetSubnetMask(24)
	sim.SetWithRTT(true)
	sim.SetSimulateType(simulator.IPTimeSummarized)
	sim.SetSlotInterval(24*time.Hour, 24)

	sim.SuperPrefetch(begin, end)

	byIntervalExamineResults := make([][]simulator.Results, 0)

	for _, op := range operationPeriods { // when operation period is...
		fmt.Printf("  Operation Period: %v, Range %s - %s", op, begin.Format("2006-01-02"), begin.Add(op*5).Add(ap).Format("2006-01-02"))
		byIntervalResult := []simulator.Results{}
		n := time.Now()
		// canSimDuration := duration - (op + ap)
		// canSimCount := int(math.Floor(canSimDuration.Hours() / op.Hours()))
		// sampleCount := int(math.Min(float64(canSimCount), 5.0))
		sampleCount := 5
		for sc := 0; sc < sampleCount; sc++ { // sampling some
			b := begin.Add(time.Duration(sc) * op)
			sim.SetTerm(b, ap, op)
			results := sim.Simulate()
			byIntervalResult = append(byIntervalResult, results)
			fmt.Print(".")
		}
		fmt.Println(" done.", time.Since(n))
		byIntervalExamineResults = append(byIntervalExamineResults, byIntervalResult)
	}

	// write
	perfContent := ""
	detecContent := ""
	for i, byIntervalResult := range byIntervalExamineResults {
		l := len(byIntervalResult)
		detecSum := 0.0
		perfSum := 0.0

		for _, r := range byIntervalResult {
			detecSum += r.Of[simulator.IPTimeSummarized].DetectionRate
			perfSum += r.Of[simulator.IPTimeSummarized].Performance
		}
		detecMean := detecSum / float64(l)
		perfMean := perfSum / float64(l)

		detecContent += fmt.Sprintf("%v,%v,%f\n", ap.Hours(), operationPeriods[i].Hours(), detecMean)
		perfContent += fmt.Sprintf("%v,%v,%f\n", ap.Hours(), operationPeriods[i].Hours(), perfMean)
	}

	// add break for gnuplot
	detecContent += "\n"
	perfContent += "\n"
	dfilename := fmt.Sprintf("%d-detec-examine.csv", int(ap.Hours()))
	pfilename := fmt.Sprintf("%d-perf-examine.csv", int(ap.Hours()))
	ioutil.WriteFile(dfilename, []byte(detecContent), 0644)
	ioutil.WriteFile(pfilename, []byte(perfContent), 0644)
}
