package plotter

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"time"

	"github.com/hiragi-gkuth/bitris-analyzer/pkg/authlog"
	"github.com/hiragi-gkuth/bitris-analyzer/pkg/db"
	"github.com/hiragi-gkuth/bitris-analyzer/pkg/net"
	"github.com/hiragi-gkuth/bitris-analyzer/pkg/summarizer"
	geo "github.com/kellydunn/golang-geo"
	"gonum.org/v1/plot"
	"gonum.org/v1/plot/plotter"
	"gonum.org/v1/plot/plotutil"
	"gonum.org/v1/plot/vg"
)

func plottingCorrelation(server db.SSHServer) {
	begin, _ := time.Parse(DateTimeFormat, "2020-09-01 00:00:00")
	end, _ := time.Parse(DateTimeFormat, "2020-10-15 00:00:00")

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
	begin, _ := time.Parse(DateTimeFormat, "2020-10-01 00:00:00")
	end, _ := time.Parse(DateTimeFormat, "2020-10-04 00:00:00")
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

func plotMyselfMapByTime(attacks authlog.AuthInfoSlice, ip net.IP, durationStr string, resolution time.Duration) {
	byLagMap := make(map[LagSlot]authlog.AuthInfoSlice)
	for lagStart := time.Duration(0); lagStart < 24*time.Hour; lagStart += resolution {
		lag := LagSlot{
			offset: 0,
			begin:  lagStart,
			end:    lagStart + resolution - 1,
		}
		byLagMap[lag] = make(authlog.AuthInfoSlice, 0)
		for _, attack := range attacks {
			dayStartTime := attack.AuthAt.Truncate(24 * time.Hour)
			fromDayStartDuration := attack.AuthAt.Sub(dayStartTime)
			if fromDayStartDuration >= lag.begin && fromDayStartDuration < lag.end {
				byLagMap[lag] = append(byLagMap[lag], attack)
			}
		}
	}
	fmt.Println("data collected")

	// Plotting
	plot, e := plot.New()
	if e != nil {
		panic(e.Error())
	}

	// labels
	plot.Title.Text = "自己相関"
	plot.X.Label.Text = "Time(hour)"
	plot.Y.Label.Text = "RTT(sec)"

	// values
	nums := plotter.Values{}
	names := make([]string, 0)

	keyOrder := make([]LagSlot, 0)
	for key := range byLagMap {
		keyOrder = append(keyOrder, key)
	}
	sort.Slice(keyOrder, func(i, j int) bool {
		return keyOrder[i].begin < keyOrder[j].begin
	})

	for _, key := range keyOrder {
		auths := byLagMap[key]
		sum := 0.0
		for _, auth := range auths {
			sum += auth.RTT
		}
		mean := sum / float64(len(auths))
		if math.IsNaN(mean) {
			mean = 0
			return
		}
		nums = append(nums, mean)
		names = append(names, (key.begin / time.Hour).String())
	}

	bar, e := plotter.NewBarChart(nums, 15)
	if e != nil {
		panic(e.Error())
	}
	bar.Color = plotutil.Color(0)
	plot.Y.Max = 0.55
	plot.Add(bar)
	plot.NominalX(names...)

	plot.Save(30*vg.Centimeter, 18*vg.Centimeter, fmt.Sprintf("dd/%s-%s.png", durationStr, ip.String()))
}

func plotCorregram(attacks authlog.AuthInfoSlice, ip net.IP, resolution time.Duration) {
	begin := attacks[0].AuthAt
	end := attacks[len(attacks)-1].AuthAt

	// 一時間ごとのRTT平均をそれぞれ取る
	data := make([]float64, 0)
	for seeker := begin; seeker.Before(end); seeker = seeker.Add(resolution) {
		attacksOnThisSlot := attacks.Where(func(ad *authlog.AuthInfo) bool {
			return ad.AuthAt.After(seeker) && ad.AuthAt.Before(seeker.Add(resolution))
		})
		sum := 0.0
		for _, attack := range attacksOnThisSlot {
			sum += attack.RTT
		}
		mean := sum / float64(len(attacksOnThisSlot))
		if math.IsNaN(mean) {
			mean = 0.0
		}
		data = append(data, mean)
	}

	// コレラグラムを求める
	// n = データ数
	// t = 時点
	// h = ラグ
	// hl = どこまでラグをずらすか
	// rtMean = 全体の平均
	// rt = その時点での値
	hl := 24 * 4
	autoCorrelation := make([]float64, 0)
	n := len(data)
	rtMean := 0.0
	for _, d := range data {
		rtMean += d
	}
	rtMean /= float64(n)
	// ラグ 0 - 96 までを求める
	for h := 0; h < hl; h++ {
		var numer float64
		for t := 0; t < n; t++ {
			rt := data[t]
			numer += math.Pow((rt - rtMean), 2)
		}
		numer /= float64(n)
		var denom float64
		for t := h; t < n; t++ {
			rt := data[t]
			rth := data[t-h]
			denom += (rt - rtMean) * (rth - rtMean)
		}
		denom /= float64(n)
		c := denom / numer
		autoCorrelation = append(autoCorrelation, c)
	}

	// Plotting
	plot, e := plot.New()
	if e != nil {
		panic(e.Error())
	}

	// labels
	plot.Title.Text = "Auto Correlation diagram"
	plot.X.Label.Text = "Lag(Hour)"
	plot.Y.Label.Text = "ACF"

	// Values
	values := plotter.Values{}
	names := make([]string, 0)
	for i, c := range autoCorrelation {
		values = append(values, c)
		names = append(names, strconv.Itoa(i+1))
	}

	bar, e := plotter.NewBarChart(values, 10)
	if e != nil {
		panic(e.Error())
	}
	bar.Color = plotutil.Color(0)
	plot.Y.Max = 1.0
	plot.Y.Min = -1.0
	plot.Add(bar)
	plot.NominalX(names...)
	plot.Save(40*vg.Centimeter, 20*vg.Centimeter, fmt.Sprintf("correlation/%s.png", ip.String()))
}

func plotRttDistanceMap(attacks authlog.AuthInfoSlice) {
	byCountry := averageByCountry(attacks)
	for point, rttMean := range byCountry {
		here := geo.NewPoint(34.877561, 135.57572)
		distance := here.GreatCircleDistance(&point)
		fmt.Printf("%.4f,%.4f\n", distance, rttMean)
	}
}

// LagSlot means slot by day
type LagSlot struct {
	offset time.Duration
	begin  time.Duration
	end    time.Duration
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
