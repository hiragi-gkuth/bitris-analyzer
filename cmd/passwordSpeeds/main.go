package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/hiragi-gkuth/bitris-analyzer/internal/authlog"
	"github.com/hiragi-gkuth/bitris-analyzer/internal/db"

	"github.com/fluent/fluent-logger-golang/fluent"
)

func main() {
	showTopScores()
	topScoreAuthTime := fetchBestScoreAuthInfo().Authtime
	fastest := float64(1000.0)

	var username string
	fmt.Print("type your name: ")
	fmt.Scan(&username)

	fmt.Println("Type [Return] to start measure. If you want to exit, type 'exit' for password")
	bufio.NewScanner(os.Stdin).Scan()

	for {
		inputStr := ""
		start := time.Now()

		fmt.Print("Password: ")
		fmt.Scanf("%s", &inputStr)

		duration := time.Since(start)

		if strings.Compare(inputStr, "exit") == 0 {
			break
		}

		if strings.Compare(inputStr, "password") != 0 {
			fmt.Println("incorrect password! try again")
			continue
		}

		fmt.Printf("OK! %.4f ms\n", duration.Seconds())
		if fastest > duration.Seconds() {
			fastest = duration.Seconds()
		}
		loggingToFluent(username, duration)
		// appendRecord(duration)
	}

	fmt.Printf("Your best score is '%.4f' seconds\n", fastest)

	if topScoreAuthTime > fastest {
		fmt.Printf("Conguratulation!!!!  Best score updated by YOU!\n")
	}
}

func loggingToFluent(username string, duration time.Duration) {
	logger, err := fluent.New(fluent.Config{
		FluentHost:    "10.1.228.31",
		FluentPort:    24224,
		FluentNetwork: "tcp",
	})

	if err != nil {
		panic(err.Error())
	}

	now := time.Now()
	postMessage := map[string]string{
		"result":         "Success",
		"user":           ascii2Hex(username),
		"password":       ascii2Hex("password"),
		"ip":             "10.1.3.10",
		"authtime":       fmt.Sprintf("%.6f", duration.Seconds()),
		"detect":         "Normal",
		"rtt":            "0.0",
		"unixtime":       fmt.Sprintf("%d", now.Unix()),
		"usec":           "0", // fmt.Sprintf("%d", int64(now.UnixNano()/1000)),
		"kex":            "0.0",
		"newkey":         "0.0",
		"server_id":      "successsample",
		"forwarder_host": "10.1.228.32",
	}
	logger.Post("cririn.go-sampler.auth.info", postMessage)
}

func ascii2Hex(asciiString string) string {
	encoded := hex.EncodeToString([]byte(asciiString))
	return encoded
}

func showTopScores() {
	fastest := fetchBestScoreAuthInfo()
	fmt.Printf("The fastest typing speed of 'password' is %v by %v!!!!\n", fastest.Authtime, fastest.User)
}

func fetchBestScoreAuthInfo() authlog.AuthInfo {
	bitris := db.NewDB(db.Cririn)
	successes := bitris.FetchSuccessSamples()
	fastest := successes.Max(func(s *authlog.AuthInfo) float64 { return s.Authtime })

	return fastest
}
