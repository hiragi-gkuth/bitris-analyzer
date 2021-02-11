package main

import (
	"fmt"
	"io/ioutil"
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

func simIPSumm(subnet int) {
	begin, _ := time.Parse(Format, Begin)
	end := begin.Add(24 * time.Hour * 31)

	s := simulator.New("uehara", "uehara")
	s.SetVerbose(false)
	s.SetSimulateType(simulator.IPSummarized)
	s.SetWithRTT(true)
	s.SuperPrefetch(begin, end.Add(24*time.Hour))

	pOperation := 24 * time.Hour

	s.SetSubnetMask(subnet)
	fmt.Println("subnet:", subnet)

	content := ""

	for h := 1; h < 24*10; h++ {
		pAnalyze := time.Duration(h) * time.Hour
		hitavg := 0.0
		detecavg := 0.0
		c := 0
		fmt.Printf("pAnalyze: %v ", pAnalyze)
		for b := begin; b.Before(end.Add(-24 * 11 * time.Hour)); b = b.Add(24 * time.Hour) {
			s.SetTerm(b, pAnalyze, pOperation)
			result := s.Simulate()
			hitavg += result.Of[simulator.IPSummarized].HitRate
			detecavg += result.Of[simulator.IPSummarized].DetectionRate
			fmt.Print(".")
			c++
		}
		hitavg = hitavg / float64(c)
		detecavg = detecavg / float64(c)
		content += fmt.Sprintf("%d,%f,%f\n", h, hitavg, detecavg)
	}

	fname := fmt.Sprintf("%d.csv", subnet)
	ioutil.WriteFile(fname, []byte(content), 0644)
}
