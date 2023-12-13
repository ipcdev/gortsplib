package gortsplib

import (
	"github.com/bluenviron/gortsplib/v4/pkg/ringbuffer"
)

// this struct contains a queue that allows to detach the routine that is reading a stream
// from the routine that is writing a stream.
//
// 该结构包含一个队列，允许将 读取流的协程 与 写入流的协程 分离。
type asyncProcessor struct {
	running bool
	buffer  *ringbuffer.RingBuffer

	done chan struct{}
}

// 分配 ring buffer 大小
func (w *asyncProcessor) allocateBuffer(size int) {
	w.buffer, _ = ringbuffer.New(uint64(size))
}

// 启动
func (w *asyncProcessor) start() {
	w.running = true
	w.done = make(chan struct{})
	go w.run()
}

// 停止
func (w *asyncProcessor) stop() {
	if w.running {
		w.buffer.Close()
		<-w.done
		w.running = false
	}
}

func (w *asyncProcessor) run() {
	defer close(w.done)

	// 不断从 ring buffer 中取数据，并执行回调
	for {
		// 从 buffer 中获取数据
		tmp, ok := w.buffer.Pull()
		if !ok {
			return
		}

		// 执行回调
		tmp.(func())()
	}
}

// 向 buffer 中写入数据
func (w *asyncProcessor) push(cb func()) bool {
	return w.buffer.Push(cb)
}
