package gortsplib

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/bluenviron/gortsplib/v4/pkg/base"
	"github.com/bluenviron/gortsplib/v4/pkg/liberrors"
)

func extractPort(address string) (int, error) {
	_, tmp, err := net.SplitHostPort(address)
	if err != nil {
		return 0, err
	}

	tmp2, err := strconv.ParseUint(tmp, 10, 16)
	if err != nil {
		return 0, err
	}

	return int(tmp2), nil
}

type sessionRequestRes struct {
	ss  *ServerSession
	res *base.Response
	err error
}

type sessionRequestReq struct {
	sc     *ServerConn
	req    *base.Request          // RTSP 请求
	id     string                 // Session ID
	create bool                   // 如果在 RTSP 服务器没有找到与 id 对应的 session，是否创建新的 session。false：不创建，没有找到的话返回 454（SessionNotFound）
	res    chan sessionRequestRes // RTSP 请求处理后的响应
}

type chGetMulticastIPReq struct {
	res chan net.IP
}

// Server is a RTSP server.
type Server struct {
	//
	// RTSP parameters (all optional except RTSPAddress)
	//
	// the RTSP address of the server, to accept connections and send and receive
	// packets with the TCP transport.
	// 服务器的 RTSP 地址，用于接受连接并通过 TCP 传输发送和接收数据包。
	RTSPAddress string
	// a port to send and receive RTP packets with the UDP transport.
	// If UDPRTPAddress and UDPRTCPAddress are filled, the server can support the UDP transport.
	// 使用 UDP 传输发送和接收 RTP 数据包的端口。
	// 如果 UDPRTPAddress 和 UDPRTCPAddress 已填写，则服务器可以支持 UDP 传输。
	UDPRTPAddress string
	// a port to send and receive RTCP packets with the UDP transport.
	// If UDPRTPAddress and UDPRTCPAddress are filled, the server can support the UDP transport.
	// 使用 UDP 传输发送和接收 RTCP 数据包的端口。
	// 如果 UDPRTPAddress 和 UDPRTCPAddress 已填写，则服务器可以支持 UDP 传输。
	UDPRTCPAddress string
	// a range of multicast IPs to use with the UDP-multicast transport.
	// If MulticastIPRange, MulticastRTPPort, MulticastRTCPPort are filled, the server
	// can support the UDP-multicast transport.
	MulticastIPRange string
	// a port to send RTP packets with the UDP-multicast transport.
	// If MulticastIPRange, MulticastRTPPort, MulticastRTCPPort are filled, the server
	// can support the UDP-multicast transport.
	MulticastRTPPort int
	// a port to send RTCP packets with the UDP-multicast transport.
	// If MulticastIPRange, MulticastRTPPort, MulticastRTCPPort are filled, the server
	// can support the UDP-multicast transport.
	MulticastRTCPPort int
	// timeout of read operations.
	// It defaults to 10 seconds
	// 读超时时间，默认 10s
	ReadTimeout time.Duration
	// timeout of write operations.
	// It defaults to 10 seconds
	// 写超时时间，默认 10s
	WriteTimeout time.Duration
	// a TLS configuration to accept TLS (RTSPS) connections.
	// 用于接受 TLS (RTSPS) 连接的 TLS 配置。
	TLSConfig *tls.Config
	// Size of the queue of outgoing packets.
	// It defaults to 256.
	WriteQueueSize int
	// maximum size of outgoing RTP / RTCP packets.
	// This must be less than the UDP MTU (1472 bytes).
	// It defaults to 1472.
	MaxPacketSize int
	// disable automatic RTCP sender reports.
	// 禁用自动 RTCP sender 报告。
	DisableRTCPSenderReports bool

	//
	// handler (optional)
	//
	// an handler to handle server events.
	// It may implement one or more of the ServerHandler* interfaces.
	//
	// 处理 服务器 事件
	// 可以实现一个或多个 ServerHandler* 接口
	Handler ServerHandler

	//
	// system functions (all optional)
	//
	// function used to initialize the TCP listener.
	// It defaults to net.Listen.
	//
	// 用于初始化 TCP listener 的函数。
	// 默认是 net.Listen。
	Listen func(network string, address string) (net.Listener, error)
	// function used to initialize UDP listeners.
	// It defaults to net.ListenPacket.
	//
	// 用于初始化 UDP listeners
	ListenPacket func(network, address string) (net.PacketConn, error)

	//
	// private
	//

	timeNow              func() time.Time // 获取当前时间函数
	senderReportPeriod   time.Duration    // 默认 10s，且未发现配置该值的地方。用于 rtcpSender。
	receiverReportPeriod time.Duration
	sessionTimeout       time.Duration
	checkStreamPeriod    time.Duration // 检查流周期

	ctx             context.Context
	ctxCancel       func()
	wg              sync.WaitGroup
	multicastNet    *net.IPNet
	multicastNextIP net.IP
	tcpListener     *serverTCPListener        // 用于监听 RTSP 客户端的请求
	udpRTPListener  *serverUDPListener        // UDP RTP 侦听器 (侦听地址端口由 s.UDPRTPAddress 配置)
	udpRTCPListener *serverUDPListener        // UDP RTCP 侦听器 (侦听地址端口由 s.UDPRTCPAddress 配置)
	sessions        map[string]*ServerSession // 保存客户端与服务端之间的 session。 key：SessionID;  value: session
	conns           map[*ServerConn]struct{}  // 保存 RTSP 客户端与服务端建立的连接
	closeError      error                     // 用于接收 runInner() 返回的错误

	// in
	chNewConn        chan net.Conn    // 当有新的 RTSP 客户端连接请求时
	chCloseConn      chan *ServerConn // 关闭连接
	chAcceptErr      chan error
	chHandleRequest  chan sessionRequestReq // RTSP 服务器处理 ServerConn 传递过来的 RTSP 请求
	chCloseSession   chan *ServerSession
	chGetMulticastIP chan chGetMulticastIPReq
}

// Start starts the server.
// 启动服务
func (s *Server) Start() error {
	// RTSP parameters
	if s.ReadTimeout == 0 {
		s.ReadTimeout = 10 * time.Second
	}
	if s.WriteTimeout == 0 {
		s.WriteTimeout = 10 * time.Second
	}
	if s.WriteQueueSize == 0 {
		s.WriteQueueSize = 256
	} else if (s.WriteQueueSize & (s.WriteQueueSize - 1)) != 0 {
		return fmt.Errorf("WriteQueueSize must be a power of two")
	}
	if s.MaxPacketSize == 0 {
		s.MaxPacketSize = udpMaxPayloadSize
	} else if s.MaxPacketSize > udpMaxPayloadSize {
		return fmt.Errorf("MaxPacketSize must be less than %d", udpMaxPayloadSize)
	}

	// system functions
	if s.Listen == nil {
		s.Listen = net.Listen
	}
	if s.ListenPacket == nil {
		s.ListenPacket = net.ListenPacket
	}

	// private
	if s.timeNow == nil {
		s.timeNow = time.Now
	}
	if s.senderReportPeriod == 0 {
		s.senderReportPeriod = 10 * time.Second
	}
	if s.receiverReportPeriod == 0 {
		s.receiverReportPeriod = 10 * time.Second
	}
	if s.sessionTimeout == 0 {
		s.sessionTimeout = 1 * 60 * time.Second
	}
	if s.checkStreamPeriod == 0 {
		s.checkStreamPeriod = 1 * time.Second
	}

	// TLS 不能使用 UDP
	if s.TLSConfig != nil && s.UDPRTPAddress != "" {
		return fmt.Errorf("TLS can't be used with UDP")
	}

	// TLS 不能使用 UDP 广播
	if s.TLSConfig != nil && s.MulticastIPRange != "" {
		return fmt.Errorf("TLS can't be used with UDP-multicast")
	}

	if s.RTSPAddress == "" {
		return fmt.Errorf("RTSPAddress not provided")
	}

	// UDPRTPAddress、UDPRTCPAddress 必须都提供
	if (s.UDPRTPAddress != "" && s.UDPRTCPAddress == "") ||
		(s.UDPRTPAddress == "" && s.UDPRTCPAddress != "") {
		return fmt.Errorf("UDPRTPAddress and UDPRTCPAddress must be used together")
	}

	// UDP
	if s.UDPRTPAddress != "" {
		rtpPort, err := extractPort(s.UDPRTPAddress)
		if err != nil {
			return err
		}

		rtcpPort, err := extractPort(s.UDPRTCPAddress)
		if err != nil {
			return err
		}

		if (rtpPort % 2) != 0 {
			return fmt.Errorf("RTP port must be even")
		}

		if rtcpPort != (rtpPort + 1) {
			return fmt.Errorf("RTP and RTCP ports must be consecutive")
		}

		s.udpRTPListener, err = newServerUDPListener(
			s.ListenPacket,
			s.WriteTimeout,
			false,
			s.UDPRTPAddress,
		)
		if err != nil {
			return err
		}

		s.udpRTCPListener, err = newServerUDPListener(
			s.ListenPacket,
			s.WriteTimeout,
			false,
			s.UDPRTCPAddress,
		)
		if err != nil {
			s.udpRTPListener.close()
			return err
		}
	}

	// 广播
	if s.MulticastIPRange != "" && (s.MulticastRTPPort == 0 || s.MulticastRTCPPort == 0) ||
		(s.MulticastRTPPort != 0 && (s.MulticastRTCPPort == 0 || s.MulticastIPRange == "")) ||
		s.MulticastRTCPPort != 0 && (s.MulticastRTPPort == 0 || s.MulticastIPRange == "") {
		if s.udpRTPListener != nil {
			s.udpRTPListener.close()
		}
		if s.udpRTCPListener != nil {
			s.udpRTCPListener.close()
		}
		return fmt.Errorf("MulticastIPRange, MulticastRTPPort and MulticastRTCPPort must be used together")
	}

	if s.MulticastIPRange != "" {
		if (s.MulticastRTPPort % 2) != 0 {
			if s.udpRTPListener != nil {
				s.udpRTPListener.close()
			}
			if s.udpRTCPListener != nil {
				s.udpRTCPListener.close()
			}
			return fmt.Errorf("RTP port must be even")
		}

		if s.MulticastRTCPPort != (s.MulticastRTPPort + 1) {
			if s.udpRTPListener != nil {
				s.udpRTPListener.close()
			}
			if s.udpRTCPListener != nil {
				s.udpRTCPListener.close()
			}
			return fmt.Errorf("RTP and RTCP ports must be consecutive")
		}

		var err error
		_, s.multicastNet, err = net.ParseCIDR(s.MulticastIPRange)
		if err != nil {
			if s.udpRTPListener != nil {
				s.udpRTPListener.close()
			}
			if s.udpRTCPListener != nil {
				s.udpRTCPListener.close()
			}
			return err
		}

		s.multicastNextIP = s.multicastNet.IP
	}

	s.ctx, s.ctxCancel = context.WithCancel(context.Background())

	s.sessions = make(map[string]*ServerSession)
	s.conns = make(map[*ServerConn]struct{})
	s.chNewConn = make(chan net.Conn)
	s.chAcceptErr = make(chan error)
	s.chCloseConn = make(chan *ServerConn)
	s.chHandleRequest = make(chan sessionRequestReq)
	s.chCloseSession = make(chan *ServerSession)
	s.chGetMulticastIP = make(chan chGetMulticastIPReq)

	var err error
	s.tcpListener, err = newServerTCPListener(s) // 创建服务端 TCP Listener，等待 RTSP 客户端建立网络连接
	if err != nil {
		if s.udpRTPListener != nil {
			// 关闭 udp RTP listener
			s.udpRTPListener.close()
		}
		if s.udpRTCPListener != nil {
			// 关闭 udp RTCP listener
			s.udpRTCPListener.close()
		}
		s.ctxCancel()
		return err
	}

	s.wg.Add(1)
	go s.run()

	return nil
}

// Close closes all the server resources and waits for them to close.
func (s *Server) Close() {
	s.ctxCancel()
	s.wg.Wait()
}

// Wait waits until all server resources are closed.
// This can happen when a fatal error occurs or when Close() is called.
func (s *Server) Wait() error {
	s.wg.Wait()
	return s.closeError
}

func (s *Server) run() {
	defer s.wg.Done()

	// 阻塞，直到 runInner() 有错误返回
	s.closeError = s.runInner()

	s.ctxCancel()

	if s.udpRTCPListener != nil {
		// 关闭 UDP RTCP Listener
		s.udpRTCPListener.close()
	}

	if s.udpRTPListener != nil {
		// 关闭 UDP RTP Listener
		s.udpRTPListener.close()
	}

	// 关闭 TCP Listener
	s.tcpListener.close()
}

func (s *Server) runInner() error {
	for {
		select {
		case <-s.ctx.Done(): // 上下文取消
			return liberrors.ErrServerTerminated{}

		case err := <-s.chAcceptErr: // TCP Listener 发生 Accept 错误
			return err

		case nconn := <-s.chNewConn: // 有新的 RTSP 客户端请求建立 TCP 连接
			// 封装 TCP 连接，创建 RTSP 服务端连接
			sc := newServerConn(s, nconn)
			s.conns[sc] = struct{}{}

		case sc := <-s.chCloseConn: // 关闭 ServerConn
			if _, ok := s.conns[sc]; !ok {
				continue
			}
			delete(s.conns, sc)
			sc.Close()

		case req := <-s.chHandleRequest: // RTSP 服务器处理 Request
			// 从 RTSP 服务器中查找是否有已存在的 session
			if ss, ok := s.sessions[req.id]; ok {
				// RTSP 服务器中有对应的 session 存在

				if !req.sc.ip().Equal(ss.author.ip()) ||
					req.sc.zone() != ss.author.zone() {
					req.res <- sessionRequestRes{
						res: &base.Response{
							StatusCode: base.StatusBadRequest,
						},
						err: liberrors.ErrServerCannotUseSessionCreatedByOtherIP{},
					}
					continue
				}

				select {
				case ss.chHandleRequest <- req: // 将 RTSP 请求交给 C/S 之间建立的 会话 处理
				case <-ss.ctx.Done():
					req.res <- sessionRequestRes{
						res: &base.Response{
							StatusCode: base.StatusBadRequest,
						},
						err: liberrors.ErrServerTerminated{},
					}
				}
			} else {
				// 没有 SessionID 对应的 session 存在

				if !req.create {
					// 服务端没有查找到与 SessionID 对应的 session，且不创建 session，返回 NotFound 错误

					req.res <- sessionRequestRes{
						res: &base.Response{
							StatusCode: base.StatusSessionNotFound,
						},
						err: liberrors.ErrServerSessionNotFound{},
					}
					continue
				}

				// 创建新的会话
				ss := newServerSession(s, req.sc)
				s.sessions[ss.secretID] = ss

				// 会话创建完车，将请求交给建立的 会话 处理
				select {
				case ss.chHandleRequest <- req:
				case <-ss.ctx.Done():
					req.res <- sessionRequestRes{
						res: &base.Response{
							StatusCode: base.StatusBadRequest,
						},
						err: liberrors.ErrServerTerminated{},
					}
				}
			}

		case ss := <-s.chCloseSession:
			if sss, ok := s.sessions[ss.secretID]; !ok || sss != ss {
				continue
			}
			delete(s.sessions, ss.secretID)
			ss.Close()

		case req := <-s.chGetMulticastIP:
			ip32 := uint32(s.multicastNextIP[0])<<24 | uint32(s.multicastNextIP[1])<<16 |
				uint32(s.multicastNextIP[2])<<8 | uint32(s.multicastNextIP[3])
			mask := uint32(s.multicastNet.Mask[0])<<24 | uint32(s.multicastNet.Mask[1])<<16 |
				uint32(s.multicastNet.Mask[2])<<8 | uint32(s.multicastNet.Mask[3])
			ip32 = (ip32 & mask) | ((ip32 + 1) & ^mask)
			ip := make(net.IP, 4)
			ip[0] = byte(ip32 >> 24)
			ip[1] = byte(ip32 >> 16)
			ip[2] = byte(ip32 >> 8)
			ip[3] = byte(ip32)
			s.multicastNextIP = ip
			req.res <- ip

		}
	}
}

// StartAndWait starts the server and waits until a fatal error.
func (s *Server) StartAndWait() error {
	err := s.Start()
	if err != nil {
		return err
	}

	return s.Wait()
}

func (s *Server) getMulticastIP() (net.IP, error) {
	res := make(chan net.IP)
	select {
	case s.chGetMulticastIP <- chGetMulticastIPReq{res: res}:
		return <-res, nil

	case <-s.ctx.Done():
		return nil, liberrors.ErrServerTerminated{}
	}
}

func (s *Server) newConn(nconn net.Conn) {
	select {
	case <-s.ctx.Done():
		// 上下文取消，关闭网络连接
		nconn.Close()

	case s.chNewConn <- nconn:
		// 交给 rtsp 服务器处理这个新的 RTSP 客户端 TCP 连接
	}
}

// TCP Listener 发生 Accept 错误
func (s *Server) acceptErr(err error) {
	select {
	case <-s.ctx.Done():

	case s.chAcceptErr <- err:
	}
}

// 关闭 ServerConn
func (s *Server) closeConn(sc *ServerConn) {
	select {
	case <-s.ctx.Done():

	case s.chCloseConn <- sc:
	}
}

func (s *Server) closeSession(ss *ServerSession) {
	select {
	case s.chCloseSession <- ss:
	case <-s.ctx.Done():
	}
}

// Server 处理 Request
func (s *Server) handleRequest(req sessionRequestReq) (*base.Response, *ServerSession, error) {
	select {
	case <-s.ctx.Done(): // 上下文取消
		return &base.Response{
			StatusCode: base.StatusBadRequest,
		}, req.sc.session, liberrors.ErrServerTerminated{}

	case s.chHandleRequest <- req: // 交给 RTSP 服务器处理 Request
		// 阻塞等待处理完成 Request
		res := <-req.res
		return res.res, res.ss, res.err

	}
}
