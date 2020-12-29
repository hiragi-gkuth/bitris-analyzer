package summarizer

import "time"

// ITimeSlot は，TimeSlotが実装すべきメソッドを定義する
type ITimeSlot interface {
	Begin() time.Duration
	End() time.Duration
	Next() ITimeSlot
	DuringInterval() bool
	IsInSlot(time time.Time) bool
}

// TimeSlot は，ある一定区間の時間を表します
type TimeSlot struct {
	EntireDuration time.Duration
	Divisions      int
	Numerator      int
}

// NewTimeSlot は，新しいTimeSlotを返す
func NewTimeSlot(entireDuration time.Duration, divisions int) ITimeSlot {
	return TimeSlot{
		EntireDuration: entireDuration,
		Divisions:      divisions,
		Numerator:      0,
	}
}

// Begin は，そのTimeSlotの開始時間のオフセットをUnixNanoで返す．最初の時刻を含む
func (t TimeSlot) Begin() time.Duration {
	return time.Duration(
		float64(t.EntireDuration.Nanoseconds()) * float64(t.Numerator) / float64(t.Divisions),
	)
}

// End は，そのTimeSlotの終了時間のオフセットをUnixNanoで返す．最後の時刻は含まない
func (t TimeSlot) End() time.Duration {
	return time.Duration(
		float64(t.EntireDuration.Nanoseconds())*float64(t.Numerator+1)/float64(t.Divisions) - 1,
	)
}

// Next は，そのTimeSlotの次のTimeSlotを新たに返す
func (t TimeSlot) Next() ITimeSlot {
	return TimeSlot{
		EntireDuration: t.EntireDuration,
		Divisions:      t.Divisions,
		Numerator:      t.Numerator + 1,
	}
}

// DuringInterval は，そのTimeSlotがちゃんと全体の範囲内に含まれているかを返す
func (t TimeSlot) DuringInterval() bool {
	return 0 <= t.Numerator && t.Numerator < t.Divisions
}

// IsInSlot は，その与えられたtimeが，そのTimeSlotの中に含まれているかどうかを返す．
func (t TimeSlot) IsInSlot(time time.Time) bool {
	// calc on UnixNano
	offset := time.UnixNano() % t.EntireDuration.Nanoseconds()
	return t.Begin().Nanoseconds() <= offset && offset <= t.End().Nanoseconds()
}
