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
		time.Duration(timeResolution)*time.Minute,
		simulator.IPSummarized|simulator.TimeSummarized, //|simulator.Legacy|simulator.IPTimeSummarized,
	)
}

func examineParamsOfSimulationIntervalAndAnalyzeRatio(
	serverID string,
	sampleCount int,
	maxDuration, timeResolution time.Duration,
	simulateType simulator.SimulateType,
) [][][]simulator.Results {
	operationPeriods := func() []time.Duration {
		ret := []time.Duration{}
		for d := timeResolution; d <= maxDuration; d += timeResolution {
			ret = append(ret, d)
		}
		return ret
	}()

	analysisPeriods := make([]time.Duration, len(operationPeriods))
	copy(analysisPeriods, operationPeriods)

	begin, _ := time.Parse("2006-01-02 15:04:05", "2020-12-01 00:00:00")
	withRTT := true
	subnetMask := 16

	// setup Simulator
	sim := simulator.New("uehara", "cririn")
	sim.SetSubnetMask(subnetMask)
	sim.SetWithRTT(withRTT)
	sim.SetSimulateType(simulateType)
	sim.SetSlotInterval(24*time.Hour, 24)

	examineResults := [][][]simulator.Results{}

	// do prefetching
	// 調査範囲全てのアクセスを取得するため， begin から begin + (maxDuration * 2) * sampleCount ぶん取得する
	sim.SuperPrefetch(begin, begin.Add(24*4*time.Hour))

	log.Println("examine params begin")
	for _, analysisPeriod := range analysisPeriods { // when analysis period is...
		fmt.Printf("Analysis Period: %v\n", analysisPeriod)
		byIntervalExamineResults := [][]simulator.Results{}
		for _, operationPeriod := range operationPeriods { // when operation period is...
			fmt.Printf("  Operation Period: %v", operationPeriod)
			byIntervalResult := []simulator.Results{}
			n := time.Now()
			for sc := 0; sc < sampleCount; sc++ { // sampling some
				b := begin.Add(time.Duration(sc) * operationPeriod)
				sim.SetTerm(b, analysisPeriod, operationPeriod)
				results := sim.Simulate()
				byIntervalResult = append(byIntervalResult, results)
				fmt.Print(".")
			}
			fmt.Println(" done.", time.Since(n))
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

	type ValuesMap map[simulator.SimulateType][]Values

	type TsvMap map[simulator.SimulateType]string

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

	// tsv content
	tsvMap := make(TsvMap)

	for ai, perAnalyzePeriod := range examineResults3d {
		for oi, perOperationPeriod := range perAnalyzePeriod {
			vMap := make(ValuesMap)

			// sum all samples for calc mean
			for _, perSamples := range perOperationPeriod {
				// per simulate types
				for simType, result := range perSamples.Of {
					if _, ok := vMap[simType]; !ok {
						vMap[simType] = make([]Values, 0)
					}
					vMap[simType] = append(vMap[simType], Values{
						Performance: result.Performance,
						Detec:       result.DetectionRate,
						MisDetec:    result.MisDetectionRate,
						HitRate:     result.HitRate,
					})
				}
			}

			for simType, values := range vMap {
				// X-axis: Analysis Period  (minute)
				// Y-axis: Operation Period (minute)
				// Z-axis: Performance      (percentage)
				tsvMap[simType] += fmt.Sprintf("%v\t%v\t%v\n",
					analysisPeriods[ai].Minutes(),
					operationPeriods[oi].Minutes(),
					calcMean(values).Performance, // calc mean
				)
			}
		}
		// new line for gnu plot
		for k := range tsvMap {
			tsvMap[k] += "\n"
		}
	}
	timestamp := time.Now().Format("20060102150405")

	// saving to tsv file
	for simType, tsvStr := range tsvMap {
		filename := fmt.Sprintf("%d-%v.tsv", simType, timestamp)
		ioutil.WriteFile(filename, []byte(tsvStr), 0644)
	}
}
