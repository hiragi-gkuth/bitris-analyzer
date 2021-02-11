package main

import (
	"fmt"
	"io/ioutil"
	"math"
	"time"

	"github.com/hiragi-gkuth/bitris-analyzer/internal/authlog"
	"github.com/hiragi-gkuth/bitris-analyzer/internal/db"
	"github.com/hiragi-gkuth/bitris-analyzer/internal/summarizer"
)

func plotCorr() {
	begin, _ := time.Parse(Format, Begin)
	end := begin.Add(31 * 24 * time.Hour)
	db := db.NewDB("10.1.228.33", 3306, "hiragi-gkuth", "emyure-ta", "uehara")
	attacks := db.FetchBetween(begin, end)

	acfForAll := calcAcf(begin, end, attacks)

	for h, rt := range acfForAll {
		fmt.Printf("%d,%f\n", h, rt)
	}

	for _, summ := range summarizer.ByIP(attacks, 16) {
		auths := summ.Auths
		if len(auths) < 1000 {
			continue
		}
		acfForThis := calcAcf(begin, end, auths)
		filename := fmt.Sprintf("%d-%s.csv", len(auths), summ.IP.String())
		content := ""
		for h, rt := range acfForThis {
			content += fmt.Sprintf("%d,%f\n", h, rt)
		}
		ioutil.WriteFile(filename, []byte(content), 0644)
	}
}

func calcAcf(begin, end time.Time, attacks authlog.AuthInfoSlice) []float64 {
	rttsPerHour := make([]float64, 0)
	res := time.Hour

	misCnt := 0

	// calc mean per hour
	for seeker := begin; seeker.Before(end); seeker = seeker.Add(res) {
		attacksOnThisSlot := attacks.Where(func(ad *authlog.AuthInfo) bool {
			return ad.AuthAt.After(seeker) && ad.AuthAt.Before(seeker.Add(res))
		})
		if len(attacksOnThisSlot) == 0 {
			rttsPerHour = append(rttsPerHour, 0.0)
			continue
		}
		sum := 0.0
		for _, attack := range attacksOnThisSlot {
			sum += attack.RTT
		}
		mean := sum / float64(len(attacksOnThisSlot))
		rttsPerHour = append(rttsPerHour, mean)
	}

	// linear interpolation
	inInterpolation := false
	iBegin := 0
	for i, v := range rttsPerHour {
		if v == 0.0 && !inInterpolation {
			inInterpolation = true
			if i == 0 {
				iBegin = i
			} else {
				iBegin = i - 1
			}
			continue
		}
		if v != 0 && inInterpolation {
			inInterpolation = false
			left := rttsPerHour[iBegin]
			right := rttsPerHour[i]
			diff := right - left
			idxDiff := i - iBegin
			for j := 0; j < idxDiff; j++ {
				v := left + (diff * float64(j) / float64(idxDiff))
				rttsPerHour[iBegin+j] = v
			}
		}
	}

	// ちゃんと線形補間できてる？
	rttContent := ""
	for i, rtt := range rttsPerHour {
		rttContent += fmt.Sprintf("%d,%f\n", i, rtt)
	}
	rttFilename := fmt.Sprintf("%s-rtt.csv", attacks[0].IP.SubnetMask(16).String())
	ioutil.WriteFile(rttFilename, []byte(rttContent), 0644)

	// calc acf graph
	// コレラグラムを求める
	// n = データ数
	// t = 時点
	// h = ラグ
	// hl = どこまでラグをずらすか
	// rtMean = 全体の平均
	// rt = その時点での値
	hl := 24 * 4
	acfs := make([]float64, 0)
	n := len(rttsPerHour)
	rtMean := 0.0
	for _, d := range rttsPerHour {
		rtMean += d
	}
	rtMean /= float64(n)
	// ラグ 0 - 96 までを求める
	for h := 0; h < hl; h++ {
		var (
			numerA float64 = 0.0
			numerB float64 = 0.0
		)
		for t := h; t < n; t++ {
			rt := rttsPerHour[t]
			rth := rttsPerHour[t-h]
			numerA += math.Pow((rt - rtMean), 2)
			numerB += math.Pow((rth - rtMean), 2)
		}
		numerA /= float64(n)
		numerB /= float64(n)
		numer := math.Sqrt(numerA) * math.Sqrt(numerB)
		var denom float64
		for t := h; t < n; t++ {
			rt := rttsPerHour[t]
			rth := rttsPerHour[t-h]
			denom += (rt - rtMean) * (rth - rtMean)
		}
		denom /= float64(n)
		c := denom / numer
		acfs = append(acfs, c)
	}
	acfs = append(acfs, float64(misCnt))
	return acfs
}
