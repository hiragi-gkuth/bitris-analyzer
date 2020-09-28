package main

import (
	"fmt"
	"time"

	geo "github.com/kellydunn/golang-geo"

	"github.com/hiragi-gkuth/bitris-analyzer/pkg/db"
	"github.com/hiragi-gkuth/bitris-analyzer/pkg/net"

	"github.com/hiragi-gkuth/bitris-analyzer/pkg/authinfo"
)

// IPPerformance is
type IPPerformance map[net.IP][]ThresholdResult

func main() {
	// begin, _ := time.Parse("2006-01-02 15:04:05", "2020-09-01 00:00:00")
	// end, _ := time.Parse("2006-01-02 15:04:05", "2020-09-07 00:00:00")

	begin, _ := time.Parse("2006-01-02 15:04:05", "2020-09-01 00:00:00")
	end, _ := time.Parse("2006-01-02 15:04:05", "2020-09-28 00:00:00")
	interval := 7 * 24 * time.Hour

	for seeker := begin; seeker.Before(end); seeker = seeker.Add(interval) {
		attacks := db.FetchBetween(seeker, seeker.Add(interval))
		byIPSummary := SummaryByIPSubnet(attacks, 16)

		for ip, auths := range byIPSummary {
			plotMyselfMapByTime(auths, ip, seeker.String(), time.Hour)
		}
	}
}

// 攻撃元の座標別にRTTのの平均値を取ったMapを返す
func averageByCountry(attacks authinfo.AuthDataSlice) map[geo.Point]float64 {
	geoRTTMap := make(map[geo.Point]float64)
	geoCounterMap := make(map[geo.Point]int)

	for _, attack := range attacks {
		// 外れ値を除外
		if attack.RTT > 2.0 {
			continue
		}
		point := *geo.NewPoint(float64(attack.GeoInfo.Latitude), float64(attack.GeoInfo.Longitude))
		if _, ok := geoRTTMap[point]; !ok {
			geoRTTMap[point] = 0.0
			geoCounterMap[point] = 0
		}
		geoRTTMap[point] += attack.RTT
		geoCounterMap[point]++
	}

	result := make(map[geo.Point]float64)
	for k, rttSum := range geoRTTMap {
		// サンプル数が少ないものを除外
		if geoCounterMap[k] < 30 {
			continue
		}
		result[k] = rttSum / float64(geoCounterMap[k])
	}
	return result
}

func byTimeThreshold() {
	begin, _ := time.Parse("2006-01-02 15:04:05", "2020-07-07 00:00:00")
	end, _ := time.Parse("2006-01-02 15:04:05", "2020-07-14 00:00:00")
	interval, _ := time.ParseDuration("1h")
	authDataList := db.FetchBetween(begin, end)

	for seeker := begin; seeker.Before(end); seeker = seeker.Add(interval) {
		s := seeker
		e := seeker.Add(interval)
		partialList := authDataList.Where(func(ad *authinfo.AuthData) bool {
			return ad.AuthAt.After(s) && ad.AuthAt.Before(e)
		})
		for perc := 0.8; perc < 0.99; perc += 0.01 {
			threshold := CalcThresholdWithRTT(partialList, perc, 5)
			fmt.Printf("%.3f,", threshold)
		}
		fmt.Printf("\n")
	}
}
