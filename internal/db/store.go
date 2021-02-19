package db

// Query do just execute sql
func (b *Bitris) Query(sql string) {
	b.DB.Exec(sql)
}
