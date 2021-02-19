// Package threshold は，しきい値データの操作機能を提供する
package threshold

import (
	"fmt"
	"strings"
	"time"
)

// Threshold is analyzed thresholds per IP, Time and so on
type Threshold struct {
	BaseThreshold float64
	OnIP          *OnIP
	OnTime        *OnTime
	OnIPTime      *OnIPTime
}

// New return new one
func New(subnetMask int, entireDuration time.Duration, divisions int) *Threshold {
	return &Threshold{
		BaseThreshold: 0.0,
		OnIP:          NewOnIP(subnetMask),
		OnTime:        NewOnTime(entireDuration, divisions),
		OnIPTime:      NewOnIPTime(subnetMask, entireDuration, divisions),
	}
}

// Show shows calculation result
func (rcv *Threshold) Show() {
	fmt.Printf("Base: %.3f\n", rcv.BaseThreshold)

	fmt.Println("OnTime:")

	for t, threshold := range rcv.OnTime.m {
		fmt.Printf("  %v ->\t %.3f\n", time.Duration(t)*time.Second, threshold)
	}

	fmt.Println("OnIPTime:")
	for ip, threshold := range rcv.OnIPTime.onIP.List() {
		fmt.Printf("  %s ->\t %.3f\n", ip, threshold)
		onTime := rcv.OnIPTime.GetByIP(ip)
		for t, thresholdForTime := range onTime.m {
			fmt.Printf("    %v ->\t %.3f\n", time.Duration(t*int64(time.Second)), thresholdForTime)
		}
	}
}

// CreateTableSQL returns create table sql for new threshold table
func (rcv *Threshold) CreateTableSQL(serverID string) string {
	now := time.Now()
	tableName := fmt.Sprintf("%s_%s", serverID, now.Format("2006010215"))

	sql := fmt.Sprintf("CREATE TABLE %s (\n"+
		"`addr` VARCHAR(64) NOT NULL,\n"+
		"`mask` INT unsigned NOT NULL,\n"+
		"`entireperiod` INT unsigned NOT NULL,\n"+
		"`div` INT unsigned NOT NULL,\n"+
		"`pos` INT unsigned NOT NULL,\n"+
		"`threshold` DOUBLE unsigned NOT NULL\n"+
		");\n", tableName)

	return sql
}

// InsertSQL returns insert sql for store threshold data
func (rcv *Threshold) InsertSQL(serverID string) string {
	now := time.Now()
	tableName := fmt.Sprintf("%s_%s", serverID, now.Format("2006010215"))

	sql := fmt.Sprintf("INSERT INTO %s VALUES\n", tableName)

	/*
		SQL insertion process.
		Table Description is
		(addr, mask, entireperiod, div, pos, threshold)
	*/
	// base threshold insertion
	sql += fmt.Sprintf("	('%s', %d, %d, %d, %d, %f),\n",
		"0.0.0.0", 0, 0, 0, 0, rcv.BaseThreshold)

	// onIP threshold insertion
	for ip, threshold := range rcv.OnIP.m {
		addr := strings.Split(ip, "/")[0]
		sql += fmt.Sprintf("	('%s', %d, %d, %d, %d, %f),\n",
			addr, rcv.OnIP.mask, 0, 0, 0, threshold)
	}

	// onTime threshold insertion
	for t, threshold := range rcv.OnTime.m {
		sec := int64(rcv.OnTime.Entire.Truncate(time.Second).Seconds())
		sql += fmt.Sprintf("	('%s', %d, %d, %d, %d, %f),\n",
			"0.0.0.0", 0, sec, rcv.OnTime.Divisions, t, threshold)
	}

	// onIPTime threshold insertion
	for ip, onTime := range rcv.OnIPTime.m {
		addr := strings.Split(ip, "/")[0]
		for t, threshold := range onTime.m {
			sec := int64(rcv.OnTime.Entire.Truncate(time.Second).Seconds())
			sql += fmt.Sprintf("	('%s', %d, %d, %d, %d, %f),\n",
				addr, rcv.OnIP.mask, sec, onTime.Divisions, t, threshold)
		}
	}
	// suffix semi colon
	sql = strings.TrimRight(sql, ",\n")
	sql += ";\n"

	return sql
}
