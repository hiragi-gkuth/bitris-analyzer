package main

import (
	"fmt"
	"time"

	"github.com/hiragi-gkuth/bitris-analyzer/internal/simulator"
)

const (
	// Format is datetime format
	Format = "2006-01-02 15:04:05"
	// Begin is begin of thesis analyze
	Begin = "2020-12-01 00:00:00"
	// End is end
	End = "2021-01-01 00:00:00"
)

func simIPSumm() {
	begin, _ := time.Parse(Format, Begin)
	end := begin.Add(24 * time.Hour * 31)

	s := simulator.New("uehara", "uehara")
	s.SetVerbose(false)
	s.SetSimulateType(simulator.IPSummarized | simulator.Legacy)
	s.SetWithRTT(true)
	s.SuperPrefetch(begin, end.Add(24*time.Hour))

	pOperation := 24 * time.Hour
	subnetMasks := []int{8, 16, 24}

	for _, mask := range subnetMasks {
		s.SetSubnetMask(mask)
		fmt.Println("subnet:", mask)

		for h := 1; h < 24*4; h++ {
			pAnalyze := time.Duration(h) * time.Hour
			hitavg := 0.0
			detecavg := 0.0
			c := 0
			for b := begin; b.Before(end.Add(-24 * 5 * time.Hour)); b = b.Add(24 * time.Hour) {
				s.SetTerm(b, pAnalyze, pOperation)
				result := s.Simulate()
				hitavg += result.Of[simulator.IPSummarized].HitRate
				detecavg += result.Of[simulator.IPSummarized].DetectionRate
				c++
			}
			hitavg = hitavg / float64(c)
			detecavg = detecavg / float64(c)
			fmt.Printf("%d,%f,%f\n", h, hitavg, detecavg)
		}
	}

}
