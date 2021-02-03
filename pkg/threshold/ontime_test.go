package threshold

import (
	"reflect"
	"testing"
	"time"
)

func TestNewOnTime(t *testing.T) {
	type args struct {
		entireDuration time.Duration
		divisions      int
	}
	tests := []struct {
		name string
		args args
		want *OnTime
	}{
		{
			name: "test new",
			args: args{
				entireDuration: 24 * time.Hour,
				divisions:      48,
			},
			want: &OnTime{
				Entire:    24 * time.Hour,
				Divisions: 48,
				unit:      24 * time.Hour / 48,
				m:         make(map[int64]float64),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewOnTime(tt.args.entireDuration, tt.args.divisions); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewOnTime() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestOnTime_Get_Set(t *testing.T) {
	type fields struct {
		Entire    time.Duration
		Divisions int
		m         map[int64]float64
		unit      time.Duration
	}
	type args struct {
		t         time.Time
		threshold float64
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		{
			name: "set entire 24 div 24",
			fields: fields{
				Entire:    24 * time.Hour,
				Divisions: 24,
				m:         make(map[int64]float64),
				unit:      24 * time.Hour / 24,
			},
			args: args{
				t:         time.Now(),
				threshold: 1.0,
			},
		},
		{
			name: "set entire 24 div 240",
			fields: fields{
				Entire:    24 * time.Hour,
				Divisions: 240,
				m:         make(map[int64]float64),
				unit:      24 * time.Hour / 240,
			},
			args: args{
				t:         time.Now(),
				threshold: 1.0,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &OnTime{
				Entire:    tt.fields.Entire,
				Divisions: tt.fields.Divisions,
				m:         tt.fields.m,
				unit:      tt.fields.unit,
			}
			o.Set(tt.args.t, tt.args.threshold)
			if threshold, ok := o.Get(time.Now()); !ok {
				t.Error("OnTime_Set(), o.m is not ok.", ok)
			} else if threshold != 1.0 {
				t.Errorf("OnTime_Set(), o.m[].threshold = %f, want = %f", threshold, tt.args.threshold)
			} else {
				t.Log("OK!", threshold)
			}
		})
	}
}
