package types

import (
	"github.com/hiragi-gkuth/bitris-analyzer/pkg/authinfo"
	"github.com/hiragi-gkuth/bitris-analyzer/pkg/net"
)

// SummaryAuth はIPによってまとめられたデータ群を示します
type SummaryAuth map[net.IP]authinfo.AuthDataSlice
