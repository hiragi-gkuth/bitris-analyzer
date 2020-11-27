package main

import (
	"time"

	"github.com/hiragi-gkuth/bitris-analyzer/pkg/simulator"
)

func main() {
	begin, _ := time.Parse("2006-01-02 15:04:05", "2020-10-01 00:00:00")
	end := begin.Add(24 * time.Hour * 7 * 4)
	interval, _ := time.ParseDuration("240h")
	analyzeDataRatio := 0.8

	for b := begin; b.Before(end); b = b.Add(interval) {
		// analyze durations
		aBegin := b
		aEnd := aBegin.Add(time.Duration(float64(interval) * analyzeDataRatio))
		// test durations
		tBegin := aEnd.Add(0)
		tEnd := tBegin.Add(time.Duration(float64(interval) * (1 - analyzeDataRatio)))

		simulator, e := simulator.NewSimulator(aBegin, aEnd, tBegin, tEnd, simulator.Legacy|simulator.IPSummarized, true)
		if e != nil {
			panic(e.Error())
		}
		simulator.Test()
	}

}

/*

func plottingCorrelation(server db.SSHServer) {
	begin, _ := time.Parse(DTF, "2020-09-01 00:00:00")
	end, _ := time.Parse(DTF, "2020-10-15 00:00:00")

	db := db.NewDB(server)

	attacks := db.FetchBetween(begin, end)
	attacksW := attacks.Where(func(ad *authlog.AuthInfo) bool {
		subnet := ad.IP.SubnetMask(16).String()
		return subnet != "222.186.0.0" && subnet != "218.92.0.0" && subnet != "193.228.0.0" && subnet != "112.85.0.0" && subnet != "111.229.0.0" && subnet != "61.177.0.0" && subnet != "49.88.0.0"
	})
	fmt.Printf("%v", len(attacksW))
	plotCorregram(attacksW, net.NewDefaultIP(), 1*time.Hour)

	byIPSummary := summarizer.ByIP(attacks, 16)
	for _, summary := range byIPSummary {
		if len(summary.Auths) > 5000 {
			plotCorregram(summary.Auths, summary.IP, 1*time.Hour)
		}
	}
}

// IPアドレス毎の過去指定日間における、平均のグラフを書く
func plottingMyselfMap(server db.SSHServer) {
	begin, _ := time.Parse(DTF, "2020-10-01 00:00:00")
	end, _ := time.Parse(DTF, "2020-10-04 00:00:00")
	interval := 7 * 24 * time.Hour

	bitris := db.NewDB(server)

	for seeker := begin; seeker.Before(end); seeker = seeker.Add(interval) {
		attacks := bitris.FetchBetween(seeker, seeker.Add(interval))
		byIPSummary := summarizer.ByIP(attacks, 16)
		for _, summary := range byIPSummary {
			plotMyselfMapByTime(summary.Auths, summary.IP, seeker.String(), time.Hour)
		}
	}
}

// 攻撃元の座標別にRTTのの平均値を取ったMapを返す
func averageByCountry(attacks authlog.AuthInfoSlice) map[geo.Point]float64 {
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
*/
