package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"time"

	"github.com/hiragi-gkuth/bitris-analyzer/internal/simulator"
)

func main() {
	examineParamsOfSimulationIntervalAndAnalyzeRatio()

}

func examineParamsOfSimulationIntervalAndAnalyzeRatio() [][][]simulator.Results {
	// setup simulation params
	serverID := "uehara"
	sampleCount := 10
	intervals := func() []time.Duration {
		ret := []time.Duration{}
		for h := 1; h <= 48*2; h++ {
			ret = append(ret, time.Duration(h)*time.Hour/2)
		}
		return ret
	}()

	ratios := func() []float64 {
		ret := []float64{}
		for i := 0; i < 99; i++ {
			ret = append(ret, float64(i)/100.0)
		}
		return ret
	}()

	begin, _ := time.Parse("2006-01-02 15:04:05", "2020-11-04 00:00:00")
	withRTT := true
	subnetMask := 16

	// setup Simulator
	sim := simulator.New(serverID)
	sim.SubnetMask(subnetMask)
	sim.WithRTT(withRTT)
	sim.SimulateType(simulator.Legacy | simulator.IPSummarized)

	examineResults := [][][]simulator.Results{}

	// do prefetching
	sim.SimulateRange(begin, begin.Add(48*time.Hour*time.Duration(sampleCount)))
	sim.Prefetch()

	log.Println("examine params begin")
	for _, ratio := range ratios {
		sim.AnalyzeRatio(ratio)
		fmt.Printf("ratio: %v\n", ratio)
		byIntervalExamineResults := [][]simulator.Results{}
		for _, interval := range intervals {
			fmt.Printf("  interval: %v", interval)
			byIntervalResult := []simulator.Results{}
			slideAmount := time.Duration(float64(interval) * ratio)
			for b := begin; b.Before(begin.Add(slideAmount * time.Duration(sampleCount))); b = b.Add(slideAmount) {
				fmt.Printf(".")
				end := b.Add(interval)
				sim.SimulateRange(b, end)
				results := sim.Simulate()
				byIntervalResult = append(byIntervalResult, results)
			}
			fmt.Println(" done.")
			byIntervalExamineResults = append(byIntervalExamineResults, byIntervalResult)
		}
		examineResults = append(examineResults, byIntervalExamineResults)
	}

	toCsv(examineResults, ratios, intervals, sampleCount)

	return examineResults
}

func toCsv(examineResults3d [][][]simulator.Results, ratios []float64, intervals []time.Duration, sampleCount int) {
	type Values struct {
		Performance float64
		Detec       float64
		MisDetec    float64
		HitRate     float64
	}

	calcMean := func(vs []Values) Values {
		sum := Values{
			Performance: 0.0,
			Detec:       0.0,
			MisDetec:    0.0,
			HitRate:     0.0,
		}
		for _, v := range vs {
			sum.Performance += v.Performance
			sum.Detec += v.Detec
			sum.MisDetec += v.MisDetec
			sum.HitRate += v.HitRate
		}
		l := float64(len(vs) + 1)
		return Values{
			Performance: sum.Performance / l,
			Detec:       sum.Detec / l,
			MisDetec:    sum.MisDetec / l,
			HitRate:     sum.HitRate / l,
		}
	}

	legacyCsv := ""
	newCsv := ""

	for ri, perRatio := range examineResults3d {
		fmt.Printf("Ratio: %.1f\n", ratios[ri])
		for ii, perInterval := range perRatio {
			fmt.Printf("  Interval: %v\n", intervals[ii])
			legacyValues := []Values{}
			ipSummaruzedValues := []Values{}
			for _, perSamples := range perInterval {
				legacy := perSamples.Of[simulator.Legacy]
				ipSummarized := perSamples.Of[simulator.IPSummarized]
				legacyValues = append(legacyValues, Values{
					Performance: legacy.Performance,
					Detec:       legacy.DetectionRate,
					MisDetec:    legacy.MisDetectionRate,
					HitRate:     0.0,
				})
				ipSummaruzedValues = append(ipSummaruzedValues, Values{
					Performance: ipSummarized.Performance,
					Detec:       ipSummarized.DetectionRate,
					MisDetec:    ipSummarized.MisDetectionRate,
					HitRate:     ipSummarized.HitRate,
				})
			}
			legacyMean := calcMean(legacyValues)
			ipSummarizedMean := calcMean(ipSummaruzedValues)

			// X-axis: AnalyzeRatio
			// Y-axis: Interval
			// Z-axis: Performance
			legacyCsv += fmt.Sprintf("%v\t%v\t%v\n", ratios[ri], ii, legacyMean.Performance)
			newCsv += fmt.Sprintf("%v\t%v\t%v\n", ratios[ri], ii, ipSummarizedMean.Performance)
		}
		legacyCsv += "\n"
		newCsv += "\n"
	}
	fmt.Print(legacyCsv)
	fmt.Print(newCsv)

	ioutil.WriteFile("new.tsv", []byte(newCsv), 0666)
	ioutil.WriteFile("legacy.tsv", []byte(legacyCsv), 0666)
}
