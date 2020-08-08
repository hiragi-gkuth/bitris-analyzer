package main

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/hiragi-gkuth/bitris-analyzer/pkg/authinfo"

	"github.com/go-sql-driver/mysql"
)

// BitrisDB is interface for logging server data
type BitrisDB struct {
	db *sql.DB
}

// GetDbConnection return db connection
func GetDbConnection() *BitrisDB {
	config := mysql.NewConfig()

	config.User = "hiragi-gkuth"
	config.Passwd = "emyure-ta"
	config.DBName = "bitris"
	config.Net = "tcp"
	config.Addr = "10.1.228.31"

	db, err := sql.Open("mysql", config.FormatDSN())

	if err != nil {
		panic(err.Error())
	}
	return &BitrisDB{
		db: db,
	}
}

// FetchLatest returns latest logs
func (b *BitrisDB) FetchLatest(limit int) []authinfo.AuthData {
	query := fmt.Sprintf("SELECT * FROM uehara LIMIT %v", limit)
	return querying(b.db, query)
}

// FetchBetween returns logs between two times, Order by latest
func (b *BitrisDB) FetchBetween(begin time.Time, end time.Time) []authinfo.AuthData {
	query := fmt.Sprintf("SELECT * FROM uehara WHERE auth_at BETWEEN '%v' AND '%v'", formatDateTime(begin), formatDateTime(end))
	fmt.Println(query)
	return querying(b.db, query)
}

// FetchByIP returns logs by IP Address.
func (b *BitrisDB) FetchByIP(ipaddr authinfo.IPAddr, subnetMask int) []authinfo.AuthData {
	subnet := ipaddr.SubnetMask(subnetMask)
	searchString := strings.ReplaceAll(subnet.String(), "0", "")
	query := fmt.Sprintf("SELECT * FROM uehara WHERE IP LIKE \"%%%v%%\"", searchString)
	return querying(b.db, query)
}

func formatDateTime(t time.Time) string {
	return t.Format("2006-01-02 15:04:05")
}

func querying(db *sql.DB, query string) []authinfo.AuthData {
	rows, err := db.Query(query)
	if err != nil {
		panic(err.Error())
	}
	defer rows.Close()

	authDataList := make([]authinfo.AuthData, 0)
	for rows.Next() {
		authDbData := rowScanner(rows)
		authDataList = append(authDataList, authDbData.ConvertToAuthData())
	}
	return authDataList
}

func rowScanner(rows *sql.Rows) authinfo.AuthDbData {
	nullableUserName := sql.NullString{}
	authDbData := authinfo.NewAuthDbData()
	err := rows.Scan(
		&authDbData.ID,
		&authDbData.Result,
		&nullableUserName,
		&authDbData.Password,
		&authDbData.IP,
		&authDbData.Authtime,
		&authDbData.Detect,
		&authDbData.RTT,
		&authDbData.AuthAt,
		&authDbData.Kex,
		&authDbData.NewKey,
	)
	if err != nil {
		panic(err.Error())
	}
	if nullableUserName.Valid {
		authDbData.User = nullableUserName.String
	} else {
		authDbData.User = ""
	}
	return authDbData
}
