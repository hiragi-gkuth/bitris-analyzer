package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/hiragi-gkuth/bitris-analyzer/internal/simulator"
)

func main() {
	serverID := fmt.Sprint(os.Args[1])
	sampleCount, _ := strconv.Atoi(os.Args[2])
	maxDuration, _ := strconv.Atoi(os.Args[3])
	timeResolution, _ := strconv.Atoi(os.Args[4])

	examineParamsOfSimulationIntervalAndAnalyzeRatio(
		serverID,
		sampleCount,
		time.Duration(maxDuration)*time.Hour,
		time.Duration(timeResolution)*time.Minute)

}

func examineParamsOfSimulationIntervalAndAnalyzeRatio(serverID string, sampleCount int, maxDuration, timeResolution time.Duration) [][][]simulator.Results {
	operationPeriods := func() []time.Duration {
		ret := []time.Duration{}
		for d := timeResolution; d <= maxDuration; d += timeResolution {
			ret = append(ret, d)
		}
		return ret
	}()

	analysisPeriods := make([]time.Duration, len(operationPeriods))
	copy(analysisPeriods, operationPeriods)

	begin, _ := time.Parse("2006-01-02 15:04:05", "2020-11-04 00:00:00")
	withRTT := true
	subnetMask := 16

	// setup Simulator
	sim := simulator.New(serverID)
	sim.SetSubnetMask(subnetMask)
	sim.SetWithRTT(withRTT)
	sim.SetSimulateType(simulator.Legacy | simulator.IPSummarized)

	examineResults := [][][]simulator.Results{}

	// do prefetching
	// 調査範囲全てのアクセスを取得するため， begin から begin + (maxDuration * 2) * sampleCount ぶん取得する
	sim.SetTerm(begin, 0, maxDuration*2*time.Duration(sampleCount))
	sim.Prefetch()

	log.Println("examine params begin")
	for _, analysisPeriod := range analysisPeriods { // when analysis period is...
		fmt.Printf("Analysis Period: %v\n", analysisPeriod)
		byIntervalExamineResults := [][]simulator.Results{}
		for _, operationPeriod := range operationPeriods { // when operation period is...
			fmt.Printf("  Operation Period: %v", operationPeriod)
			byIntervalResult := []simulator.Results{}
			for sc := 0; sc < sampleCount; sc++ { // sampling some
				// simulation offset slides "operationPeriod" per sample
				b := begin.Add(time.Duration(sc) * operationPeriod)
				sim.SetTerm(b, analysisPeriod, operationPeriod)
				results := sim.Simulate()
				byIntervalResult = append(byIntervalResult, results)
				fmt.Print(".")
			}
			fmt.Println(" done.")
			byIntervalExamineResults = append(byIntervalExamineResults, byIntervalResult)
		}
		examineResults = append(examineResults, byIntervalExamineResults)
	}
	toCsv(examineResults, sampleCount, analysisPeriods, operationPeriods)

	return examineResults
}

func toCsv(examineResults3d [][][]simulator.Results, sampleCount int, analysisPeriods, operationPeriods []time.Duration) {
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

	for ai, perAnalyzePeriod := range examineResults3d {
		for oi, perOperationPeriod := range perAnalyzePeriod {
			legacyValues := []Values{}
			ipSummaruzedValues := []Values{}
			for _, perSamples := range perOperationPeriod {
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

			// X-axis: Analysis Period  (minute)
			// Y-axis: Operation Period (minute)
			// Z-axis: Performance      (percentage)
			legacyCsv += fmt.Sprintf("%v\t%v\t%v\n",
				analysisPeriods[ai].Minutes(),
				operationPeriods[oi].Minutes(),
				legacyMean.Performance)
			newCsv += fmt.Sprintf("%v\t%v\t%v\n",
				analysisPeriods[ai].Minutes(),
				operationPeriods[oi].Minutes(),
				ipSummarizedMean.Performance)

		}
		legacyCsv += "\n"
		newCsv += "\n"
	}
	timestamp := time.Now().Format("20060102150405")
	ioutil.WriteFile(fmt.Sprintf("ipsumm-%d-%v.tsv", sampleCount, timestamp), []byte(newCsv), 0666)
	ioutil.WriteFile(fmt.Sprintf("legacy-%d-%v.tsv", sampleCount, timestamp), []byte(legacyCsv), 0666)
}
