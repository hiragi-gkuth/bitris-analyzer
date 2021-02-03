package threshold

import (
	"net"
	"reflect"
	"testing"
)

func TestNewOnIP(t *testing.T) {
	type args struct {
		subnetMask int
	}
	tests := []struct {
		name string
		args args
		want *OnIP
	}{
		{
			"new",
			args{
				subnetMask: 24,
			},
			&OnIP{
				mask: 24,
				m:    make(map[string]float64),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewOnIP(tt.args.subnetMask); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewOnIP() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestOnIP_Set_Get(t *testing.T) {
	type fields struct {
		mask int
		m    map[string]float64
	}
	type args struct {
		ipStr     string
		threshold float64
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		{
			"set 10.11.12.13",
			fields{
				mask: 24,
				m:    make(map[string]float64),
			},
			args{
				ipStr:     "10.11.12.13",
				threshold: 1.0,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &OnIP{
				mask: tt.fields.mask,
				m:    tt.fields.m,
			}
			o.Set(tt.args.ipStr, tt.args.threshold)

			thre, ok := o.Get(net.IPv4(10, 11, 12, 236))
			if !ok {
				t.Error("OnIP_Get(), o.m is not ok.", ok)
			} else if thre != 1.0 {
				t.Errorf("OnTime_Set(), o.m[].threshold = %f, want = %f", thre, tt.args.threshold)
			} else {
				t.Log("OK!", thre)
			}
		})
	}
}
