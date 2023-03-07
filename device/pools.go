/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"sync"
	"sync/atomic"
)

// WaitPool 等待池？
type WaitPool struct {
	// 存储池，应该是用于链接池
	pool sync.Pool
	// 协调器，当资源状态发生变化，则通知被阻塞的协程
	cond sync.Cond
	// 哦吼，人家命名都是lock，一般都是mu，学习一下
	lock sync.Mutex
	// 目前存储数
	count atomic.Uint32
	// 池中最大存储数，max在该类中为常量，所以不用加锁，注：当max为0时，则无限从pool中获取数据
	max uint32
}

// NewWaitPool 新建等待池
func NewWaitPool(max uint32, new func() any) *WaitPool {
	p := &WaitPool{pool: sync.Pool{New: new}, max: max}
	p.cond = sync.Cond{L: &p.lock}
	return p
}

// Get 获取等待池中的数据
func (p *WaitPool) Get() any {
	// 如果max不是零，说明需要等待
	if p.max != 0 {
		p.lock.Lock()
		// 当数据量比max大时，进行等待
		for p.count.Load() >= p.max {
			p.cond.Wait()
		}
		// 调取数据数加一
		p.count.Add(1)
		p.lock.Unlock()
	}
	// 返回数据
	return p.pool.Get()
}

// Put 将数据返回给存储池
func (p *WaitPool) Put(x any) {
	p.pool.Put(x)
	// 如果max是0，则不触发cond相关逻辑
	if p.max == 0 {
		return
	}
	// 这里的意思是数量减一，但有问题的是，当max不等于0而count为0时但依旧put话会出问题
	p.count.Add(^uint32(0))
	// 发送信号， 让Get方法取消等待
	p.cond.Signal()
}

// PopulatePools 新建存储池， 好家伙，这三个都是无限存储
func (device *Device) PopulatePools() {
	// 返回是最大值byte数组存储池
	device.pool.messageBuffers = NewWaitPool(PreallocatedBuffersPerPool, func() any {
		return new([MaxMessageSize]byte)
	})
	// 返回是输入队列元素存储池
	device.pool.inboundElements = NewWaitPool(PreallocatedBuffersPerPool, func() any {
		return new(QueueInboundElement)
	})
	// 返回是输出队列元素存储池
	device.pool.outboundElements = NewWaitPool(PreallocatedBuffersPerPool, func() any {
		return new(QueueOutboundElement)
	})
}

/*
 * 以下是三个get三个put，没啥可说的
 */

func (device *Device) GetMessageBuffer() *[MaxMessageSize]byte {
	return device.pool.messageBuffers.Get().(*[MaxMessageSize]byte)
}

func (device *Device) PutMessageBuffer(msg *[MaxMessageSize]byte) {
	device.pool.messageBuffers.Put(msg)
}

func (device *Device) GetInboundElement() *QueueInboundElement {
	return device.pool.inboundElements.Get().(*QueueInboundElement)
}

func (device *Device) PutInboundElement(elem *QueueInboundElement) {
	elem.clearPointers()
	device.pool.inboundElements.Put(elem)
}

func (device *Device) GetOutboundElement() *QueueOutboundElement {
	return device.pool.outboundElements.Get().(*QueueOutboundElement)
}

func (device *Device) PutOutboundElement(elem *QueueOutboundElement) {
	elem.clearPointers()
	device.pool.outboundElements.Put(elem)
}
