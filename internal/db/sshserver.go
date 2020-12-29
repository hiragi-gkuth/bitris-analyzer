// Package db は，いっぱい機能を提供します
package db

// SSHServer type express log targets
type SSHServer int

const (
	// Uehara is a main logging server, all logs are attack
	Uehara SSHServer = iota
	// Cririn is public server, some of logs are attack
	Cririn
)

// TableName returns actual tablesname
func (sss SSHServer) TableName() string {
	switch sss {
	case Uehara:
		return "uehara"
	case Cririn:
		return "cririn"
	default:
		panic("Unknown SSH Server")
	}
}
