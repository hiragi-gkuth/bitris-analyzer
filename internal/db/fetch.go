package db

import (
	"fmt"
	"strings"
	"time"

	"github.com/hiragi-gkuth/bitris-analyzer/internal/authlog"
	"github.com/hiragi-gkuth/bitris-analyzer/internal/net"
)

// FetchSuccessSamples returns all success with password authentication
func (b *Bitris) FetchSuccessSamples() authlog.AuthInfoSlice {
	query := fmt.Sprintf("SELECT * FROM successsample WHERE result LIKE '%%Suc%%' AND password LIKE '70617373%%'")
	return querying(query, b.DB)
}

// FetchAll returns all authlog
func (b *Bitris) FetchAll() authlog.AuthInfoSlice {
	query := fmt.Sprintf("SELECT * FROM %s", b.ServerID)
	return querying(query, b.DB)
}

// FetchLatest returns latest logs
func (b *Bitris) FetchLatest(limit int) authlog.AuthInfoSlice {
	query := fmt.Sprintf("SELECT * FROM %s ORDER BY id DESC LIMIT %v", b.ServerID, limit)
	return querying(query, b.DB)
}

// FetchBetween returns logs between two times, Order by latest
func (b *Bitris) FetchBetween(begin time.Time, end time.Time) authlog.AuthInfoSlice {
	query := fmt.Sprintf("SELECT * FROM %s WHERE unixtime BETWEEN '%v' AND '%v'", b.ServerID, begin.Unix(), end.Unix())
	return querying(query, b.DB)
}

// FetchByIP returns logs by IP Address.
func (b *Bitris) FetchByIP(ip net.IP, subnetMask int) authlog.AuthInfoSlice {
	subnet := ip.SubnetMask(subnetMask)
	searchString := strings.ReplaceAll(subnet.String(), "0", "")
	query := fmt.Sprintf("SELECT * FROM %s WHERE IP LIKE \"%%%v%%\"", b.ServerID, searchString)
	return querying(query, b.DB)
}
