package db

// Config は，データベースサーバの設定値
type Config struct {
	ServerID string
	Host     string
	User     string
	Pass     string
	DBName   string
}
