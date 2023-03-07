/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"container/list"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

/*
 * 以下是对加密算法的一些感悟
 * C/S两端都生成属于自己的公私钥，然后双端互换公钥
 * 双端通过对端的公钥与本端的私钥通过Curve25519算法各生成一个ShareKey(肯定是不同的)
 * 在正常的使用方法中，数据发送前，通过ShareKey加密，随后再使用AES进行第二次加密
 * 对端获取密文后，先使用AES解密，随后可以使用本端的ShareKey对请求进行二次解密
 */

// Peer 一个模块点，对应一个客户端
type Peer struct {
	// 是否正在运行
	isRunning atomic.Bool
	// 主要是保护端点，但通常在修改peer时使用
	sync.RWMutex // Mostly protects endpoint, but is generally taken whenever we modify peer

	keypairs Keypairs
	// 握手类
	handshake Handshake
	// 上层设备类
	device *Device
	// 应该是网络数据流通通道
	endpoint          conn.Endpoint
	stopping          sync.WaitGroup // routines pending stop
	txBytes           atomic.Uint64  // bytes send to peer (endpoint)
	rxBytes           atomic.Uint64  // bytes received from peer
	lastHandshakeNano atomic.Int64   // nano seconds since epoch

	disableRoaming bool

	// 各项时间表
	timers struct {
		// 握手重发时间
		retransmitHandshake *Timer
		// 发送Keepalive包时间
		sendKeepalive *Timer
		// 新建握手时间
		newHandshake *Timer
		// TODO：还不知道这是啥
		zeroKeyMaterial *Timer
		// 持续Keepalive包时间
		persistentKeepalive *Timer
		// 握手尝试次数
		handshakeAttempts atomic.Uint32
		// 需要另一个Keepalive？TODO：这边还不知道是啥意思
		needAnotherKeepalive atomic.Bool
		// 是否在最后一分钟内发送过握手？应该是缓存机制
		sentLastMinuteHandshake atomic.Bool
	}

	state struct {
		sync.Mutex // protects against concurrent Start/Stop
	}

	queue struct {
		staged   chan *QueueOutboundElement // staged packets before a handshake is available
		outbound *autodrainingOutboundQueue // sequential ordering of udp transmission
		inbound  *autodrainingInboundQueue  // sequential ordering of tun writing
	}

	cookieGenerator             CookieGenerator
	trieEntries                 list.List
	persistentKeepaliveInterval atomic.Uint32
}

// NewPeer 新建一个Peer - NoisePublicKey为32位的bytes
func (device *Device) NewPeer(pk NoisePublicKey) (*Peer, error) {
	// 如果device被关掉了，则返回error
	if device.isClosed() {
		return nil, errors.New("device closed")
	}

	// lock resources
	// TODO：后面再看
	device.staticIdentity.RLock()
	defer device.staticIdentity.RUnlock()

	// peers：map[NoisePublicKey]*Peer，上锁
	device.peers.Lock()
	defer device.peers.Unlock()

	// check if over limit
	// 如果peers的长度会大于等于最大值，即65536，则返回error
	if len(device.peers.keyMap) >= MaxPeers {
		return nil, errors.New("too many peers")
	}

	// create peer
	// 新建一个peer
	peer := new(Peer)
	// 不知道为啥这也要上锁
	peer.Lock()
	defer peer.Unlock()
	// 通过public key初始化cookie类
	peer.cookieGenerator.Init(pk)
	// peer回存上层设备类
	peer.device = device
	// TODO：不是很懂，下次再看
	peer.queue.outbound = newAutodrainingOutboundQueue(device)
	peer.queue.inbound = newAutodrainingInboundQueue(device)
	peer.queue.staged = make(chan *QueueOutboundElement, QueueStagedSize)

	// map public key
	// 判断之前是否存在
	_, ok := device.peers.keyMap[pk]
	if ok {
		return nil, errors.New("adding existing peer")
	}

	// pre-compute DH
	// 获取握手实例
	handshake := &peer.handshake
	handshake.mutex.Lock()
	// 通过对端公钥与本端私钥生成ShareKey
	handshake.precomputedStaticStatic, _ = device.staticIdentity.privateKey.sharedSecret(pk)
	// 存储对端的长期公钥
	handshake.remoteStatic = pk
	handshake.mutex.Unlock()

	// reset endpoint
	// 重设置endpoint
	peer.endpoint = nil

	// init timers
	peer.timersInit()

	// add
	device.peers.keyMap[pk] = peer

	return peer, nil
}

func (peer *Peer) SendBuffer(buffer []byte) error {
	peer.device.net.RLock()
	defer peer.device.net.RUnlock()

	if peer.device.isClosed() {
		return nil
	}

	peer.RLock()
	defer peer.RUnlock()

	if peer.endpoint == nil {
		return errors.New("no known endpoint for peer")
	}

	err := peer.device.net.bind.Send(buffer, peer.endpoint)
	if err == nil {
		peer.txBytes.Add(uint64(len(buffer)))
	}
	return err
}

func (peer *Peer) String() string {
	// The awful goo that follows is identical to:
	//
	//   base64Key := base64.StdEncoding.EncodeToString(peer.handshake.remoteStatic[:])
	//   abbreviatedKey := base64Key[0:4] + "…" + base64Key[39:43]
	//   return fmt.Sprintf("peer(%s)", abbreviatedKey)
	//
	// except that it is considerably more efficient.
	src := peer.handshake.remoteStatic
	b64 := func(input byte) byte {
		return input + 'A' + byte(((25-int(input))>>8)&6) - byte(((51-int(input))>>8)&75) - byte(((61-int(input))>>8)&15) + byte(((62-int(input))>>8)&3)
	}
	b := []byte("peer(____…____)")
	const first = len("peer(")
	const second = len("peer(____…")
	b[first+0] = b64((src[0] >> 2) & 63)
	b[first+1] = b64(((src[0] << 4) | (src[1] >> 4)) & 63)
	b[first+2] = b64(((src[1] << 2) | (src[2] >> 6)) & 63)
	b[first+3] = b64(src[2] & 63)
	b[second+0] = b64(src[29] & 63)
	b[second+1] = b64((src[30] >> 2) & 63)
	b[second+2] = b64(((src[30] << 4) | (src[31] >> 4)) & 63)
	b[second+3] = b64((src[31] << 2) & 63)
	return string(b)
}

func (peer *Peer) Start() {
	// should never start a peer on a closed device
	if peer.device.isClosed() {
		return
	}

	// prevent simultaneous start/stop operations
	peer.state.Lock()
	defer peer.state.Unlock()

	if peer.isRunning.Load() {
		return
	}

	device := peer.device
	device.log.Verbosef("%v - Starting", peer)

	// reset routine state
	peer.stopping.Wait()
	peer.stopping.Add(2)

	peer.handshake.mutex.Lock()
	peer.handshake.lastSentHandshake = time.Now().Add(-(RekeyTimeout + time.Second))
	peer.handshake.mutex.Unlock()

	peer.device.queue.encryption.wg.Add(1) // keep encryption queue open for our writes

	peer.timersStart()

	device.flushInboundQueue(peer.queue.inbound)
	device.flushOutboundQueue(peer.queue.outbound)
	go peer.RoutineSequentialSender()
	go peer.RoutineSequentialReceiver()

	peer.isRunning.Store(true)
}

func (peer *Peer) ZeroAndFlushAll() {
	device := peer.device

	// clear key pairs

	keypairs := &peer.keypairs
	keypairs.Lock()
	device.DeleteKeypair(keypairs.previous)
	device.DeleteKeypair(keypairs.current)
	device.DeleteKeypair(keypairs.next.Load())
	keypairs.previous = nil
	keypairs.current = nil
	keypairs.next.Store(nil)
	keypairs.Unlock()

	// clear handshake state

	handshake := &peer.handshake
	handshake.mutex.Lock()
	device.indexTable.Delete(handshake.localIndex)
	handshake.Clear()
	handshake.mutex.Unlock()

	peer.FlushStagedPackets()
}

func (peer *Peer) ExpireCurrentKeypairs() {
	handshake := &peer.handshake
	handshake.mutex.Lock()
	peer.device.indexTable.Delete(handshake.localIndex)
	handshake.Clear()
	peer.handshake.lastSentHandshake = time.Now().Add(-(RekeyTimeout + time.Second))
	handshake.mutex.Unlock()

	keypairs := &peer.keypairs
	keypairs.Lock()
	if keypairs.current != nil {
		keypairs.current.sendNonce.Store(RejectAfterMessages)
	}
	if next := keypairs.next.Load(); next != nil {
		next.sendNonce.Store(RejectAfterMessages)
	}
	keypairs.Unlock()
}

func (peer *Peer) Stop() {
	peer.state.Lock()
	defer peer.state.Unlock()

	if !peer.isRunning.Swap(false) {
		return
	}

	peer.device.log.Verbosef("%v - Stopping", peer)

	peer.timersStop()
	// Signal that RoutineSequentialSender and RoutineSequentialReceiver should exit.
	peer.queue.inbound.c <- nil
	peer.queue.outbound.c <- nil
	peer.stopping.Wait()
	peer.device.queue.encryption.wg.Done() // no more writes to encryption queue from us

	peer.ZeroAndFlushAll()
}

func (peer *Peer) SetEndpointFromPacket(endpoint conn.Endpoint) {
	if peer.disableRoaming {
		return
	}
	peer.Lock()
	peer.endpoint = endpoint
	peer.Unlock()
}
