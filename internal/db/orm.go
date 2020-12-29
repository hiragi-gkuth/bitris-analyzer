package db

import (
	"database/sql"
	"time"

	"github.com/ip2location/ip2location-go"

	"github.com/hiragi-gkuth/bitris-analyzer/internal/authlog"
)

// querying execute sql from raw string
func querying(query string, db *sql.DB) []*authlog.AuthInfo {
	geoDB, err := ip2location.OpenDB("../../assets/geo/IP2LOCATION-LITE-DB5.BIN")

	if err != nil {
		panic(err.Error())
	}

	// now := time.Now()
	rows, err := db.Query(query)
	if err != nil {
		panic(err.Error())
	}
	defer rows.Close()
	// fmt.Printf("query time: %v\n", time.Since(now))

	authInfoList := authlog.AuthInfoSlice{}
	// now = time.Now()
	for rows.Next() {
		authRawInfo := mapper(rows)
		authInfoList = append(authInfoList, authRawInfo.ConvertToAuthInfo(geoDB))
	}
	// fmt.Printf("convert time: %v\n", time.Since(now))
	return authInfoList
}

func mapper(rows *sql.Rows) authlog.AuthRawInfo {
	nullableUserName := sql.NullString{}
	nullablePassword := sql.NullString{}
	authRawInfo := authlog.NewAuthRawInfo()
	err := rows.Scan(
		&authRawInfo.ID,
		&authRawInfo.Result,
		&nullableUserName,
		&nullablePassword,
		&authRawInfo.IP,
		&authRawInfo.Authtime,
		&authRawInfo.Detect,
		&authRawInfo.RTT,
		&authRawInfo.Unixtime,
		&authRawInfo.Usec,
		&authRawInfo.Kex,
		&authRawInfo.NewKey,
	)
	if err != nil {
		panic(err.Error())
	}
	if nullableUserName.Valid {
		authRawInfo.User = nullableUserName.String
	} else {
		authRawInfo.User = ""
	}
	if nullablePassword.Valid {
		authRawInfo.Password = nullablePassword.String
	} else {
		authRawInfo.Password = ""
	}
	return authRawInfo
}

func formatDateTime(t time.Time) string {
	return t.Format("2006-01-02 15:04:05")
}
