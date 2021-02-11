package main

import (
	"fmt"
	"time"

	"github.com/hiragi-gkuth/bitris-analyzer/internal/analyzer"
	"github.com/hiragi-gkuth/bitris-analyzer/internal/authlog"
	"github.com/hiragi-gkuth/bitris-analyzer/internal/simulator"
)

func count() {
	begin, _ := time.Parse(Format, "2020-12-21 00:00:00")
	auths := fetchAnalyzeAuths("2020-12-21 00:00:00", 31*24*time.Hour)
	ts := 0
	c := 0

	for i := 0; i < 31; i++ {
		b := begin.Add(time.Duration(i) * 24 * time.Hour)
		e := b.Add(240 * time.Hour)

		partial := auths.Where(func(a *authlog.AuthInfo) bool {
			return !a.AuthAt.Before(b) && a.AuthAt.Before(e)
		})

		c += len(partial)
		ts += 240
	}

	fmt.Printf("count: %d, hours: %d\n", c, ts)
}

func evaluate() {
	eBegin := "2021-01-15 00:00:00"
	// TODO: set this param
	ap := 240 * time.Hour
	op := 24 * time.Hour

	begin, _ := time.Parse(Format, eBegin)
	end := begin.Add(20 * 24 * time.Hour)
	ueharaResults := simulateUehara(begin, end, ap, op)
	shimaokaResults, uR := simulateShimaoka(begin, end, ap, op)

	content := ""
	for i := 0; i < len(shimaokaResults); i++ {
		t := begin.Add(op * time.Duration(i))

		ur := ueharaResults[i]
		sr := shimaokaResults[i]
		sur := uR[i]

		l := fmt.Sprintf("%v,%f,%f,%f,%f,%f,%f,%f,%f,%f\n", t.Format("2006-01-02"),
			ur.DetectionRate, ur.MisDetectionRate, ur.Performance(),
			// 0.0, 0.0, 0.0,
			// 0.0, 0.0, 0.0)
			sr.DetectionRate, sr.MisDetectionRate, sr.Performance(),
			sur.DetectionRate, sur.MisDetectionRate, sur.Performance())

		content += l
	}
	fmt.Print(content)
}

func simulateShimaoka(begin, end time.Time, ap, op time.Duration) (analyzer.DetectionsSlice, analyzer.DetectionsSlice) {
	s := simulator.New("uehara", "cririn")
	s.SetSimulateType(simulator.IPTimeSummarized | simulator.Legacy)
	s.SetWithRTT(true)
	s.SetVerbose(true)
	s.SuperPrefetch(begin, end)

	// TODO: set
	s.SetSlotInterval(24*time.Hour, 24)
	s.SetSubnetMask(24)

	// detecs
	detectionsSlice := analyzer.DetectionsSlice{}
	udetectionsSlice := analyzer.DetectionsSlice{}

	csts := []time.Duration{}
	// simulation
	for b := begin; b.Before(end.Add(-(ap + op))); b = b.Add(op) {
		s.SetTerm(b, ap, op)
		results := s.Simulate()
		its := results.Of[simulator.IPTimeSummarized]
		itu := results.Of[simulator.Legacy]

		csts = append(csts, its.CalcTime)

		detections := analyzer.Detections{
			Authtime:         its.BaseThreshold,
			DetectionRate:    its.DetectionRate,
			MisDetectionRate: its.MisDetectionRate,
		}
		detectionsSlice = append(detectionsSlice, &detections)

		udetections := analyzer.Detections{
			Authtime:         itu.BaseThreshold,
			DetectionRate:    itu.DetectionRate,
			MisDetectionRate: itu.MisDetectionRate,
		}
		udetectionsSlice = append(udetectionsSlice, &udetections)
	}
	fmt.Printf("shimaoka threshold calc times\n")
	for _, cst := range csts {
		fmt.Printf("%v\n", cst)
	}
	return detectionsSlice, udetectionsSlice
}

// use not actual simulator
func simulateUehara(begin, end time.Time, ap, op time.Duration) analyzer.DetectionsSlice {
	aBegin := "2020-12-21 00:00:00"
	oBegin := "2021-01-27 00:00:00"

	analyze := fetchAnalyzeAuths(aBegin, 240*time.Hour)
	operation := fetchOperationAuths(oBegin, 31*24*time.Hour)
	regulars := fetchSuccessAuths()

	// calc threshold
	cst := time.Now()
	calculator := analyzer.NewThresholdCalculator(analyze, regulars, false)
	threshold := calculator.CalcBestThreshold(0.001, 2.0, 0.001)
	thresholdTime := time.Since(cst)

	fmt.Printf("ueahara calctime: %v\n", thresholdTime)

	// detecs
	detectionsSlice := analyzer.DetectionsSlice{}

	// simulation
	for b := begin.Add(ap); b.Before(end.Add(-op)); b = b.Add(op) {
		e := b.Add(op)
		fmt.Printf("%v - %v", b, e)
		simOperations := operation.Where(func(a *authlog.AuthInfo) bool {
			return !a.AuthAt.Before(b) && a.AuthAt.Before(e)
		})

		detecCnt := 0
		misDetecCnt := 0
		fmt.Println(threshold)
		for _, auth := range simOperations {
			if auth.Authtime < threshold.Authtime {
				detecCnt++
			}
		}

		for _, auth := range regulars {
			if auth.Authtime >= threshold.Authtime {
				misDetecCnt++
			}
		}

		detecRate := float64(detecCnt) / float64(len(simOperations))
		misDetecRate := 1.0 - float64(misDetecCnt)/float64(len(regulars))

		detections := analyzer.Detections{
			Authtime:         threshold.Authtime,
			DetectionRate:    detecRate,
			MisDetectionRate: misDetecRate,
		}
		detectionsSlice = append(detectionsSlice, &detections)
	}

	return detectionsSlice
}
