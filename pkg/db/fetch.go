package db

import (
	"fmt"
	"strings"
	"time"

	"github.com/hiragi-gkuth/bitris-analyzer/pkg/authinfo"
	"github.com/hiragi-gkuth/bitris-analyzer/pkg/net"
)

// FetchSuccessSamples returns all success with password authentication
func FetchSuccessSamples() authinfo.AuthDataSlice {
	query := fmt.Sprintf("SELECT * FROM successsample WHERE result LIKE '%%Suc%%' AND password LIKE '70617373%%'")
	return Querying(query)
}

// FetchLatest returns latest logs
func FetchLatest(limit int) authinfo.AuthDataSlice {
	query := fmt.Sprintf("SELECT * FROM uehara ORDER BY id DESC LIMIT %v", limit)
	return Querying(query)
}

// FetchBetween returns logs between two times, Order by latest
func FetchBetween(begin time.Time, end time.Time) authinfo.AuthDataSlice {
	query := fmt.Sprintf("SELECT * FROM uehara WHERE unixtime BETWEEN '%v' AND '%v'", begin.Unix(), end.Unix())
	return Querying(query)
}

// FetchByIP returns logs by IP Address.
func FetchByIP(ip net.IP, subnetMask int) authinfo.AuthDataSlice {
	subnet := ip.SubnetMask(subnetMask)
	searchString := strings.ReplaceAll(subnet.String(), "0", "")
	query := fmt.Sprintf("SELECT * FROM uehara WHERE IP LIKE \"%%%v%%\"", searchString)
	return Querying(query)
}
