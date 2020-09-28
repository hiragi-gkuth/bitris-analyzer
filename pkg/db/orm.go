package db

import (
	"database/sql"
	"time"

	"github.com/ip2location/ip2location-go"

	"github.com/hiragi-gkuth/bitris-analyzer/pkg/authinfo"
)

// Querying execute sql from raw string
func Querying(query string) []*authinfo.AuthData {
	// start := time.Now()

	db := getDbConnection()
	geoDb, err := ip2location.OpenDB("../../assets/geo/IP2LOCATION-LITE-DB5.BIN")

	if err != nil {
		panic(err.Error())
	}

	rows, err := db.Query(query)
	if err != nil {
		panic(err.Error())
	}
	defer rows.Close()
	// fmt.Printf("Query: %s\n", time.Since(start))

	authDataList := make([]*authinfo.AuthData, 0)
	// start = time.Now()
	for rows.Next() {
		authDbData := mapper(rows)
		authDataList = append(authDataList, authDbData.ConvertToAuthData(geoDb))
	}
	// fmt.Printf("Convert: %s\n", time.Since(start))
	return authDataList
}

func mapper(rows *sql.Rows) authinfo.AuthDbData {
	nullableUserName := sql.NullString{}
	nullablePassword := sql.NullString{}
	authDbData := authinfo.NewAuthDbData()
	err := rows.Scan(
		&authDbData.ID,
		&authDbData.Result,
		&nullableUserName,
		&nullablePassword,
		&authDbData.IP,
		&authDbData.Authtime,
		&authDbData.Detect,
		&authDbData.RTT,
		&authDbData.Unixtime,
		&authDbData.Usec,
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
	if nullablePassword.Valid {
		authDbData.Password = nullablePassword.String
	} else {
		authDbData.Password = ""
	}
	return authDbData
}

func formatDateTime(t time.Time) string {
	return t.Format("2006-01-02 15:04:05")
}
