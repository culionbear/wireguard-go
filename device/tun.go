/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"fmt"

	"golang.zx2c4.com/wireguard/tun"
)

const DefaultMTU = 1420

func (device *Device) RoutineTUNEventReader() {
	device.log.Verbosef("Routine: event worker - started")
	// 返回与设备相关的事件的恒定通道
	for event := range device.tun.device.Events() {
		// 如果是修改MTU事件
		if event&tun.EventMTUUpdate != 0 {
			// 获取切片值
			mtu, err := device.tun.device.MTU()
			if err != nil {
				device.log.Errorf("Failed to load updated MTU of device: %v", err)
				continue
			}
			if mtu < 0 {
				device.log.Errorf("MTU not updated to negative value: %v", mtu)
				continue
			}
			var tooLarge string
			// 如果切片值超过了最大值，则mtu设置为最大值。
			if mtu > MaxContentSize {
				tooLarge = fmt.Sprintf(" (too large, capped at %v)", MaxContentSize)
				mtu = MaxContentSize
			}
			// Swap原子地将new存储到x中并返回前一个值。
			old := device.tun.mtu.Swap(int32(mtu))
			if int(old) != mtu {
				device.log.Verbosef("MTU updated: %v%s", mtu, tooLarge)
			}
		}

		if event&tun.EventUp != 0 {
			device.log.Verbosef("Interface up requested")
			device.Up()
		}

		if event&tun.EventDown != 0 {
			device.log.Verbosef("Interface down requested")
			device.Down()
		}
	}

	device.log.Verbosef("Routine: event worker - stopped")
}
