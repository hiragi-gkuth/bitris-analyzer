package simulator

// Threshold は，OpenSSHサーバ上におけるしきい値のデータ構造を模倣する構造体
type Threshold struct {
	Base    float64
	Offsets map[interface{}]float64
}
