// Package bytecounter contains a io.ReadWriter wrapper that allows to count read and written bytes.
package bytecounter

import (
	"io"
	"sync/atomic"
)

// ByteCounter is a io.ReadWriter wrapper that allows to count read and written bytes.
// ByteCounter 是一个 io.ReadWriter 包装器，允许计算读取和写入的字节数。
//
// 包装 TCP 连接，添加收发字节数统计能力
type ByteCounter struct {
	rw       io.ReadWriter
	received *uint64
	sent     *uint64
}

// New allocates a ByteCounter.
func New(rw io.ReadWriter, received *uint64, sent *uint64) *ByteCounter {
	if received == nil {
		received = new(uint64)
	}
	if sent == nil {
		sent = new(uint64)
	}

	return &ByteCounter{
		rw:       rw,
		received: received,
		sent:     sent,
	}
}

// Read implements io.ReadWriter.
// 从 TCP 连接中读取数据到 p，并累加收到的字节数
// 返回本次读取到的字节数
func (bc *ByteCounter) Read(p []byte) (int, error) {
	n, err := bc.rw.Read(p)
	atomic.AddUint64(bc.received, uint64(n))
	return n, err
}

// Write implements io.ReadWriter.
// 向 TCP 连接中写入数据 p，并累加本次写入的字节数
// 返回本次写入的字节数
func (bc *ByteCounter) Write(p []byte) (int, error) {
	n, err := bc.rw.Write(p)
	atomic.AddUint64(bc.sent, uint64(n))
	return n, err
}

// BytesReceived returns the number of bytes received.
func (bc *ByteCounter) BytesReceived() uint64 {
	return atomic.LoadUint64(bc.received)
}

// BytesSent returns the number of bytes sent.
func (bc *ByteCounter) BytesSent() uint64 {
	return atomic.LoadUint64(bc.sent)
}
