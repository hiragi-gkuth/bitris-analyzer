package summarizer

import (
	"github.com/hiragi-gkuth/bitris-analyzer/internal/authlog"
	geo "github.com/kellydunn/golang-geo"
)

// ByDistanceSummary is summary of GeoPoint(lat, long)
type ByDistanceSummary struct {
	GeoPoint    geo.Point // is key
	RTT         float64   // pseudo RTT with sec unit
	Distance    float64   // km unit
	CountryCode string    // like "JP", "US", "CN"...
	Auths       authlog.AuthInfoSlice
}

// ByDistanceSummaryMap is summaries of GeoPoint
type ByDistanceSummaryMap map[geo.Point]*ByDistanceSummary

// ByDistance returns by distance summary of auths
func ByDistance(attacks authlog.AuthInfoSlice, from *geo.Point) ByDistanceSummaryMap {
	outlier := 2.0 // second
	summaryMap := make(ByDistanceSummaryMap)

	for _, attack := range attacks {
		// 外れ値を除外
		if attack.RTT > outlier {
			continue
		}
		point := *geo.NewPoint(float64(attack.GeoInfo.Latitude), float64(attack.GeoInfo.Longitude))
		summ, ok := summaryMap[point]

		if !ok {
			summ = &ByDistanceSummary{
				GeoPoint:    point,
				RTT:         0,
				Distance:    point.GreatCircleDistance(from),
				CountryCode: attack.GeoInfo.Country_short,
				Auths:       authlog.AuthInfoSlice{},
			}
		}

		summ.RTT += attack.RTT
		summ.Auths = append(summ.Auths, attack)
	}

	// calc means
	for _, summ := range summaryMap {
		summ.RTT /= float64(len(summ.Auths))
	}
	return summaryMap
}
