package main

import (
	"fmt"
	"time"
)

func main() {
	bitris := GetDbConnection()
	begin, _ := time.Parse("2006-01-02 15:04:05", "2020-08-01 00:00:00")
	end, _ := time.Parse("2006-01-02 15:04:05", "2020-08-02 00:00:00")

	authDataList := bitris.FetchBetween(begin, end)
	summariedSub := SummaryByIPSubnet(authDataList, 16)

	for ip, authDataList := range summariedSub {
		if len(authDataList) < 10 {
			continue
		}
		thre := CalcThreshold(authDataList, 0.95, 2.0)
		fmt.Printf("%v: %.2f\n", ip, thre)
	}

	// for ip, authDataList := range summariedSub {
	// 	fmt.Printf("IP: %v -> count: %v\n", ip, len(authDataList))
	// }
}
