package main

import (
	"fmt"
	"io/ioutil"
	"time"

	"github.com/hiragi-gkuth/bitris-analyzer/internal/simulator"
)

func exTimeDiv() {
	content := ""

	begin, _ := time.Parse(Format, Begin)
	end := begin.Add(31 * 24 * time.Hour)

	s := simulator.New("uehara", "uehara")
	s.SetSimulateType(simulator.IPTimeSummarized)
	s.SetSubnetMask(16)
	s.SetVerbose(false)
	s.SetWithRTT(true)
	s.SuperPrefetch(begin, end.Add(24*time.Hour))

	op := 24 * time.Hour
	ap := 24 * time.Hour
	for i := 2; i <= 120; i++ {
		s.SetSlotInterval(24*time.Hour, i)

		fmt.Printf("div: %d", i)

		detecMean := 0.0
		c := 0
		for b := begin; b.Before(end); b = b.Add(24 * time.Hour) {
			s.SetTerm(b, ap, op)
			results := s.Simulate()
			detecMean += results.Of[simulator.IPTimeSummarized].DetectionRate
			c++
			fmt.Print(".")
		}
		fmt.Println("")

		detecMean /= float64(c)
		content += fmt.Sprintf("%d,%f\n", i, detecMean)
	}

	ioutil.WriteFile("timediv.csv", []byte(content), 0644)
}
