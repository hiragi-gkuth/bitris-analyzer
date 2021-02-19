package main

import (
	"os"
	"strconv"
	"time"

	"github.com/hiragi-gkuth/bitris-analyzer/internal/net"
)

func main() {
	// callExamine()
	// callPlotCorr()
	callGeoJSON()
	// callCurrency()
	// callIPSummAnalyze()
	// callTimeDiv()
	// evaluate()
	// count()
}

func callCurrency() {
	auths := fetchAllAuths()
	listCurrency(auths)
}

func callGeoJSON() {
	auths := fetchAllAuths()

	toGeoJSON(auths, net.NewDefaultIP())

	// for _, summ := range summarizer.ByIP(auths, 16) {
	// 	subnet := summ.IP
	// 	a := summ.Auths

	// 	if len(a) < 8000 {
	// 		continue
	// 	}

	// 	toGeoJSON(a, subnet)
	// }
}

func callPlotCorr() {
	plotCorr()
}

func callExamine() {
	ap, _ := strconv.Atoi(os.Args[1])
	apDuration := time.Duration(ap) * time.Hour

	opBegin, _ := strconv.Atoi(os.Args[2])
	opEnd, _ := strconv.Atoi(os.Args[3])

	ops := []time.Duration{}

	for i := opBegin; i <= opEnd; i++ {
		ops = append(ops, time.Duration(i)*time.Hour)
	}

	examine(apDuration, ops)
}

func callIPSummAnalyze() {
	subnet, _ := strconv.Atoi(os.Args[1])
	simIPSumm(subnet)
}

func callTimeDiv() {
	exTimeDiv()
}
