/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package tai64n

import (
	"bytes"
	"encoding/binary"
	"time"
)

const (
	// TimestampSize 时间戳长度
	TimestampSize = 12
	base          = uint64(0x400000000000000a)
	whitenerMask  = uint32(0x1000000 - 1)
)

// Timestamp 时间戳
type Timestamp [TimestampSize]byte

// stamp 获取时间戳
func stamp(t time.Time) Timestamp {
	var tai64n Timestamp
	// TODO：TAI64N算法，后续补充
	secs := base + uint64(t.Unix())
	nano := uint32(t.Nanosecond()) &^ whitenerMask
	binary.BigEndian.PutUint64(tai64n[:], secs)
	binary.BigEndian.PutUint32(tai64n[8:], nano)
	return tai64n
}

// Now 获取当前时间戳
func Now() Timestamp {
	return stamp(time.Now())
}

// After 比较时间
func (t1 Timestamp) After(t2 Timestamp) bool {
	return bytes.Compare(t1[:], t2[:]) > 0
}

// String 转为时间
func (t Timestamp) String() string {
	return time.Unix(int64(binary.BigEndian.Uint64(t[:8])-base), int64(binary.BigEndian.Uint32(t[8:12]))).String()
}
