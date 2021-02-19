package main

import (
	"fmt"
	"io/ioutil"
	"sort"
	"strconv"
	"strings"

	"github.com/hiragi-gkuth/bitris-analyzer/internal/authlog"
	"github.com/hiragi-gkuth/bitris-analyzer/internal/net"
	"github.com/paulmach/orb"
	"github.com/paulmach/orb/geojson"
)

type kv struct {
	key   string
	value int
}

func listCurrency(attacks authlog.AuthInfoSlice) {
	countryCnt := make(map[string]int)

	for _, attack := range attacks {
		currency := attack.GeoInfo.Country_short

		if _, ok := countryCnt[currency]; !ok {
			countryCnt[currency] = 1
		}
		c := countryCnt[currency]
		c++
		countryCnt[currency] = c
	}

	ckv := []kv{}
	for k, v := range countryCnt {
		ckv = append(ckv, kv{
			key:   k,
			value: v,
		})
	}

	sort.Slice(ckv, func(i, j int) bool { return ckv[i].value < ckv[j].value })
	fmt.Printf("All: %d count\n", len(attacks))
	for _, kv := range ckv {
		if kv.value < 1000 {
			continue
		}
		fmt.Printf("%s -> %d(%.3f%%)\n", kv.key, kv.value, (float64(kv.value) / float64(len(attacks)) * 100))
	}
}

func toGeoJSON(attacks authlog.AuthInfoSlice, ip net.IP) {
	exists := make(map[string]int)

	for _, attack := range attacks {
		lat := float64(attack.GeoInfo.Latitude)
		long := float64(attack.GeoInfo.Longitude)
		key := fmt.Sprintf("%f,%f", long, lat)
		// continue if p is already exists
		if _, ok := exists[key]; !ok {
			exists[key] = 0
		}
		exists[key]++
	}

	// max
	max := 0
	for _, cnt := range exists {
		if max < cnt {
			max = cnt
		}
	}

	geoCollections := geojson.NewFeatureCollection()

	for geo, cnt := range exists {
		long, _ := strconv.ParseFloat(strings.Split(geo, ",")[0], 64)
		lat, _ := strconv.ParseFloat(strings.Split(geo, ",")[1], 64)

		p := orb.Point{long, lat}
		f := geojson.NewFeature(p)

		perc := float64(cnt) / float64(max)

		sizeStr := "medium"

		if perc > 0.66 {
			sizeStr = "large"
		} else if perc < 0.33 {
			sizeStr = "small"
		}
		lightness := int(perc * 256)
		f.Properties["marker-size"] = sizeStr
		f.Properties["marker-color"] = fmt.Sprintf("#%02x%02x%02x", lightness, lightness, lightness)

		geoCollections.Append(f)
	}

	b, _ := geoCollections.MarshalJSON()

	filename := fmt.Sprintf("%d-%s.geojson", len(attacks), ip.String())

	ioutil.WriteFile(filename, b, 0644)
}
