/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"runtime"
	"sync"
)

// An outboundQueue is a channel of QueueOutboundElements awaiting encryption.
// An outboundQueue is ref-counted using its wg field.
// An outboundQueue created with newOutboundQueue has one reference.
// Every additional writer must call wg.Add(1).
// Every completed writer must call wg.Done().
// When no further writers will be added,
// call wg.Done to remove the initial reference.
// When the refcount hits 0, the queue's channel is closed.

// 上述翻译
// outboundQueue是等待加密的QueueOutboundElements通道。
// outboundQueue使用它的wg字段进行引用计数。
// 用newOutboundQueue创建的outboundQueue有一个引用。
// 每个额外的写入器必须调用wg.Add(1)。
// 每个完成的写入都必须调用wg.Done()。
// 当不再添加writer时，调用wg。删除初始引用。
// 当refcount达到0时，队列的通道被关闭。
type outboundQueue struct {
	// 新建元素通道
	c  chan *QueueOutboundElement
	wg sync.WaitGroup
}

func newOutboundQueue() *outboundQueue {
	q := &outboundQueue{
		c: make(chan *QueueOutboundElement, QueueOutboundSize),
	}
	q.wg.Add(1)
	go func() {
		// 等待wg.Done，后close通道
		q.wg.Wait()
		close(q.c)
	}()
	return q
}

// A inboundQueue is similar to an outboundQueue; see those docs.

// 上述翻译
// inboundQueue类似于outboundQueue；看看那些文件。
type inboundQueue struct {
	c  chan *QueueInboundElement
	wg sync.WaitGroup
}

func newInboundQueue() *inboundQueue {
	q := &inboundQueue{
		c: make(chan *QueueInboundElement, QueueInboundSize),
	}
	q.wg.Add(1)
	go func() {
		q.wg.Wait()
		close(q.c)
	}()
	return q
}

// A handshakeQueue is similar to an outboundQueue; see those docs.

// 上述翻译
// handshakeQueue类似于outboundQueue;看看那些文件。
type handshakeQueue struct {
	c  chan QueueHandshakeElement
	wg sync.WaitGroup
}

func newHandshakeQueue() *handshakeQueue {
	q := &handshakeQueue{
		c: make(chan QueueHandshakeElement, QueueHandshakeSize),
	}
	q.wg.Add(1)
	go func() {
		q.wg.Wait()
		close(q.c)
	}()
	return q
}

type autodrainingInboundQueue struct {
	c chan *QueueInboundElement
}

// newAutodrainingInboundQueue returns a channel that will be drained when it gets GC'd.
// It is useful in cases in which is it hard to manage the lifetime of the channel.
// The returned channel must not be closed. Senders should signal shutdown using
// some other means, such as sending a sentinel nil values.

// 上述翻译
// newAutodrainingInboundQueue返回一个通道，当它被回收时将被清空。
// 在很难管理通道生命周期的情况下是有用的。
// 返回的通道不能关闭发送者使用时应发出关机信号
// 一些其他的方法，例如发送一个哨兵nil值。
func newAutodrainingInboundQueue(device *Device) *autodrainingInboundQueue {
	q := &autodrainingInboundQueue{
		c: make(chan *QueueInboundElement, QueueInboundSize),
	}
	runtime.SetFinalizer(q, device.flushInboundQueue)
	return q
}

func (device *Device) flushInboundQueue(q *autodrainingInboundQueue) {
	for {
		select {
		case elem := <-q.c:
			elem.Lock()
			device.PutMessageBuffer(elem.buffer)
			device.PutInboundElement(elem)
		default:
			return
		}
	}
}

type autodrainingOutboundQueue struct {
	c chan *QueueOutboundElement
}

// newAutodrainingOutboundQueue returns a channel that will be drained when it gets GC'd.
// It is useful in cases in which is it hard to manage the lifetime of the channel.
// The returned channel must not be closed. Senders should signal shutdown using
// some other means, such as sending a sentinel nil values.
// All sends to the channel must be best-effort, because there may be no receivers.
func newAutodrainingOutboundQueue(device *Device) *autodrainingOutboundQueue {
	q := &autodrainingOutboundQueue{
		c: make(chan *QueueOutboundElement, QueueOutboundSize),
	}
	runtime.SetFinalizer(q, device.flushOutboundQueue)
	return q
}

func (device *Device) flushOutboundQueue(q *autodrainingOutboundQueue) {
	for {
		select {
		case elem := <-q.c:
			elem.Lock()
			device.PutMessageBuffer(elem.buffer)
			device.PutOutboundElement(elem)
		default:
			return
		}
	}
}
