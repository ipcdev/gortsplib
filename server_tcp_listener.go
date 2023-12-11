package gortsplib

import (
	"net"
)

// RTSP 服务器的 TCP 侦听器
// 接收 RTSP 客户端请求建立 TCP 连接，并将 连接交给 RTSP 服务器进行下一步处理
type serverTCPListener struct {
	s  *Server      // RTSP 服务器
	ln net.Listener // TCP Listener，用于与 客户端建立 TCP 连接
}

func newServerTCPListener(
	s *Server,
) (*serverTCPListener, error) {
	// 初始化 TCP Listener
	ln, err := s.Listen(restrictNetwork("tcp", s.RTSPAddress))
	if err != nil {
		return nil, err
	}

	sl := &serverTCPListener{
		s:  s,
		ln: ln,
	}

	s.wg.Add(1)
	go sl.run()

	return sl, nil
}

// 关闭 TCP Listener
func (sl *serverTCPListener) close() {
	sl.ln.Close()
}

func (sl *serverTCPListener) run() {
	defer sl.s.wg.Done()

	for {
		// 等待 RTSP 客户端请求建立 TCP 连接
		nconn, err := sl.ln.Accept()
		if err != nil {
			sl.s.acceptErr(err) // TCP Listener 发生 Accept 错误
			return
		}

		// 将 TCP 连接交给 RTSP 服务器进行封装，以及下一步处理
		sl.s.newConn(nconn)
	}
}
