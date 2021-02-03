package main

import (
	"fmt"

	"github.com/hiragi-gkuth/bitris-analyzer/internal/authlog"
	geo "github.com/kellydunn/golang-geo"
)

// DistAuthsMap is dist-auth map
type DistAuthsMap map[int]authlog.AuthInfoSlice

// DistAuths is dist-auth map
type DistAuths struct {
	distInInt int
	auths     authlog.AuthInfoSlice
}

// DistAuthsSlice is dist-auth slice
type DistAuthsSlice []*DistAuths

func (rcv DistAuthsMap) toSlice() DistAuthsSlice {
	idxMax := 0
	for i := range rcv {
		if idxMax < i {
			idxMax = i
		}
	}

	slice := make(DistAuthsSlice, idxMax+1)
	for i := range slice {
		dist := i * 1000
		auths, ok := rcv[i]
		if !ok {
			slice[i] = &DistAuths{
				distInInt: dist,
				auths:     make(authlog.AuthInfoSlice, 0),
			}
			continue
		}
		slice[i] = &DistAuths{
			distInInt: dist,
			auths:     auths,
		}
	}
	return slice
}

func boxplot(auths authlog.AuthInfoSlice) {
	// kutc pos
	here := geo.NewPoint(34.87804088572501, 135.57553952884635)
	distAuthsMap := make(DistAuthsMap)
	auths = auths.Where(func(a *authlog.AuthInfo) bool { return a.RTT < 2.0 })
	// construct distrange - auths map
	for _, auth := range auths {
		attackerPos := geo.NewPoint(float64(auth.GeoInfo.Latitude), float64(auth.GeoInfo.Longitude))
		distance := int(here.GreatCircleDistance(attackerPos))
		// devide auths per 1000 km
		idx := distance / 1000

		if _, ok := distAuthsMap[idx]; !ok {
			distAuthsMap[idx] = make(authlog.AuthInfoSlice, 0)
		}
		distAuthsMap[idx] = append(distAuthsMap[idx], auth)
	}

	distAuthsSlice := distAuthsMap.toSlice()

	// srf := func(a *authlog.AuthInfo) float64 {
	// 	return a.RTT
	// }

	for _, distAuths := range distAuthsSlice {
		xlabel := fmt.Sprintf("%d-%d", distAuths.distInInt, distAuths.distInInt+1000)

		for _, auth := range distAuths.auths {
			fmt.Printf("%s,%f\n", xlabel, auth.RTT)
		}
		// mean := func() float64 {
		// 	s := 0.0
		// 	for _, auth := range distAuths.auths {
		// 		s += srf(auth)
		// 	}
		// 	return s / float64(len(distAuths.auths))
		// }()
		// min := distAuths.auths.Min(srf)
		// max := distAuths.auths.Max(srf)
		// _, p25 := distAuths.auths.Percentile(0.25, srf)
		// _, p50 := distAuths.auths.Percentile(0.5, srf)
		// _, p75 := distAuths.auths.Percentile(0.75, srf)

		// fmt.Printf("%s,%f,%f,%f,%f,%f,%f\n", xlabel, mean, min.RTT, p25.RTT, p50.RTT, p75.RTT, max.RTT)
	}
}
