package threshold

import (
	"database/sql"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
)

// Repository は，検知モデルとDBデータとの相互変換，やり取りを行う
type Repository struct {
	ServerID string
	DBConn   *sql.DB
}

// NewRepository returns new Repository
func NewRepository(serverID string, config mysql.Config) *Repository {
	log.Print(config.FormatDSN())
	db, e := sql.Open("mysql", config.FormatDSN())
	if e != nil {
		panic(e)
	}
	return &Repository{
		ServerID: serverID,
		DBConn:   db,
	}
}

// Save は，しきい値データをDBに保存する
func (rcv *Repository) Save(thresholds *Threshold) {
	createTableSQL := rcv.generateCreateTableSQL()
	insertSQL := rcv.generateInsertSQL(thresholds)
	_, e := rcv.DBConn.Exec(createTableSQL)
	if e != nil {
		panic(e)
	}
	_, e = rcv.DBConn.Exec(insertSQL)
	if e != nil {
		panic(e)
	}
}

// FetchModel は，DBからデータを取得し，検知モデルを構築する
func (rcv *Repository) FetchModel(subnetMask int, entireDuration time.Duration, divisions int) *Threshold {
	sql := rcv.generateSelectSQL()

	rows, e := rcv.DBConn.Query(sql)
	if e != nil {
		panic(e)
	}

	idsModel := New(subnetMask, entireDuration, divisions)

	// orm
	var (
		addr            string
		mask            int
		entirePeriodNum int
		div             int
		pos             int
		threshold       float64
	)

	for rows.Next() {
		e = rows.Scan(
			&addr, &mask, &entirePeriodNum, &div, &pos, &threshold,
		)
		if e != nil {
			panic(e)
		}

		entirePeriod := time.Second * time.Duration(entirePeriodNum)

		// baseThreshold
		if addr == "0.0.0.0" && mask == 0 && entirePeriod == 0 && div == 0 && pos == 0 {
			idsModel.BaseThreshold = threshold
			continue
		}

		// onIP threshold
		if entirePeriod == 0 && div == 0 && pos == 0 {
			idsModel.OnIP.Set(addr, threshold)
			idsModel.OnIPTime.SetForIP(addr, threshold)
			continue
		}

		// onTime threshold
		if addr == "0.0.0.0" && mask == 0 {
			unit := entirePeriod / time.Duration(div)
			t := time.Now().Truncate(entirePeriod).Add(unit * time.Duration(pos))
			idsModel.OnTime.Set(t, threshold)
		}

		// onIPTime
		unit := entirePeriod / time.Duration(div)
		t := time.Now().Truncate(entirePeriod).Add(unit * time.Duration(pos))
		idsModel.OnIPTime.SetForIPTime(addr, t, threshold)
	}
	return idsModel
}

func (rcv *Repository) generateSelectSQL() string {
	return fmt.Sprintf("SELECT * FROM %s", getTableName(rcv.ServerID))
}

func (rcv *Repository) generateCreateTableSQL() string {
	sql := fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s (\n"+
		"`addr` VARCHAR(64) NOT NULL,\n"+
		"`mask` INT unsigned NOT NULL,\n"+
		"`entireperiod` INT unsigned NOT NULL,\n"+
		"`div` INT unsigned NOT NULL,\n"+
		"`pos` INT unsigned NOT NULL,\n"+
		"`threshold` DOUBLE unsigned NOT NULL\n"+
		");\n", getTableName(rcv.ServerID))

	return sql
}

func (rcv *Repository) generateInsertSQL(thresholds *Threshold) string {
	sql := fmt.Sprintf("INSERT INTO %s VALUES\n", getTableName(rcv.ServerID))

	/*
		SQL insertion process.
		Table Description is
		VALUES (
			addr (string like "0.0.0.0"),
			mask (integer like 16),
			entireperiod (integer like 86400),
			div (integer like 24),
			pos (integer like 5),
			threshold (double like 0.24)
		)
	*/
	// base threshold insertion
	sql += fmt.Sprintf("	('%s', %d, %d, %d, %d, %f),\n",
		"0.0.0.0", 0, 0, 0, 0, thresholds.BaseThreshold)

	// onIP threshold insertion
	for ip, threshold := range thresholds.OnIP.m {
		addr := strings.Split(ip, "/")[0]
		sql += fmt.Sprintf("	('%s', %d, %d, %d, %d, %f),\n",
			addr, thresholds.OnIP.mask, 0, 0, 0, threshold)
	}

	// onTime threshold insertion
	for t, threshold := range thresholds.OnTime.m {
		entirePeriod := int(thresholds.OnTime.Entire.Seconds())
		pos := t / int64(entirePeriod/thresholds.OnTime.Divisions)
		sql += fmt.Sprintf("	('%s', %d, %d, %d, %d, %f),\n",
			"0.0.0.0", 0, entirePeriod, thresholds.OnTime.Divisions, pos, threshold)
	}

	// onIPTime threshold insertion
	for ip, onTime := range thresholds.OnIPTime.m {
		addr := strings.Split(ip, "/")[0]
		for t, threshold := range onTime.m {
			entirePeriod := int(onTime.Entire.Seconds())
			pos := t / int64(entirePeriod/onTime.Divisions)
			sql += fmt.Sprintf("	('%s', %d, %d, %d, %d, %f),\n",
				addr, thresholds.OnIP.mask, entirePeriod, onTime.Divisions, pos, threshold)
		}
	}
	// suffix semi colon
	sql = strings.TrimRight(sql, ",\n")
	sql += ";\n"

	return sql
}

func getTableName(serverID string) string {
	now := time.Now()
	tableName := fmt.Sprintf("%s_%s", serverID, now.Format("2006010215"))

	return tableName
}
