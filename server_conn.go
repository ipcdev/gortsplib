package gortsplib

import (
	"context"
	"crypto/tls"
	"net"
	gourl "net/url"
	"strconv"
	"strings"
	"time"

	"github.com/bluenviron/gortsplib/v4/pkg/base"
	"github.com/bluenviron/gortsplib/v4/pkg/bytecounter"
	"github.com/bluenviron/gortsplib/v4/pkg/conn"
	"github.com/bluenviron/gortsplib/v4/pkg/description"
	"github.com/bluenviron/gortsplib/v4/pkg/liberrors"
	"github.com/bluenviron/gortsplib/v4/pkg/url"
)

// 从请求头中获取 sessionID
func getSessionID(header base.Header) string {
	if h, ok := header["Session"]; ok && len(h) == 1 {
		return h[0]
	}
	return ""
}

func serverSideDescription(d *description.Session, contentBase *url.URL) *description.Session {
	out := &description.Session{
		Title:     d.Title,
		FECGroups: d.FECGroups,
		Medias:    make([]*description.Media, len(d.Medias)),
	}

	for i, medi := range d.Medias {
		mc := &description.Media{
			Type: medi.Type,
			ID:   medi.ID,
			// Direction: skipped for the moment
			// we have to use trackID=number in order to support clients
			// like the Grandstream GXV3500.
			Control: "trackID=" + strconv.FormatInt(int64(i), 10),
			Formats: medi.Formats,
		}

		// always use the absolute URL of the track as control attribute, in order
		// to fix compatibility between GStreamer and URLs with queries.
		// (when a relative control is used, GStreamer puts it between path and query,
		// instead of appending it to the URL).
		u, _ := mc.URL(contentBase)
		mc.Control = u.String()

		out.Medias[i] = mc
	}

	return out
}

type readReq struct {
	req *base.Request // RTSP 请求
	res chan error    // 阻塞等待服务器处理完 RTSP 请求。发生错误则写入 error；无错误发生则将响应写入 TCP 网络连接
}

// ServerConn is a server-side RTSP connection.
// 包装客户端与服务端之间的 TCP 连接，进行网络数据的收发、统计、解析
type ServerConn struct {
	s *Server // RTSP 服务器

	nconn      net.Conn                 // TCP 网络连接
	remoteAddr *net.TCPAddr             // 根据 nconn 得出客户端地址
	bc         *bytecounter.ByteCounter // 包装 nconn（TCP连接） 并添加计算读写字节数的能力
	conn       *conn.Conn               // 包装 bc 用于读写 RTSP 请求

	ctx       context.Context
	ctxCancel func()

	userData interface{} // 与连接关联的用户数据
	session  *ServerSession

	// in
	chReadRequest   chan readReq // 从 tcp 连接中读取到 Request 后会写到这个 channel
	chReadError     chan error   // 从网络连接中读取数据发生错误
	chRemoveSession chan *ServerSession

	// out
	done chan struct{}
}

func newServerConn(
	s *Server,
	nconn net.Conn,
) *ServerConn {
	ctx, ctxCancel := context.WithCancel(s.ctx)

	// TLS 配置
	if s.TLSConfig != nil {
		nconn = tls.Server(nconn, s.TLSConfig)
	}

	sc := &ServerConn{
		s:               s,
		nconn:           nconn,
		bc:              bytecounter.New(nconn, nil, nil),
		ctx:             ctx,
		ctxCancel:       ctxCancel,
		remoteAddr:      nconn.RemoteAddr().(*net.TCPAddr),
		chReadRequest:   make(chan readReq),
		chReadError:     make(chan error),
		chRemoveSession: make(chan *ServerSession),
		done:            make(chan struct{}),
	}

	s.wg.Add(1)
	go sc.run()

	return sc
}

// Close closes the ServerConn.
// 关闭 ServerConn
func (sc *ServerConn) Close() {
	sc.ctxCancel()
}

// NetConn returns the underlying net.Conn.
// 返回底层 TCP 连接
func (sc *ServerConn) NetConn() net.Conn {
	return sc.nconn
}

// BytesReceived returns the number of read bytes.
// 返回 RTSP 服务器读取到的字节数
func (sc *ServerConn) BytesReceived() uint64 {
	return sc.bc.BytesReceived()
}

// BytesSent returns the number of written bytes.
// 返回 RTSP 服务器发送出去的字节数
func (sc *ServerConn) BytesSent() uint64 {
	return sc.bc.BytesSent()
}

// SetUserData sets some user data associated to the connection.
// 设置与连接关联的一些用户数据。
func (sc *ServerConn) SetUserData(v interface{}) {
	sc.userData = v
}

// UserData returns some user data associated to the connection.
// 返回与连接关联的一些用户数据。
func (sc *ServerConn) UserData() interface{} {
	return sc.userData
}

// 返回 RTSP 客户端 IP
func (sc *ServerConn) ip() net.IP {
	return sc.remoteAddr.IP
}

func (sc *ServerConn) zone() string {
	return sc.remoteAddr.Zone
}

func (sc *ServerConn) run() {
	defer sc.s.wg.Done()
	defer close(sc.done)

	// 判断 Server.Handler 是否实现了 ServerHandlerOnConnOpen 接口
	if h, ok := sc.s.Handler.(ServerHandlerOnConnOpen); ok {
		h.OnConnOpen(&ServerHandlerOnConnOpenCtx{
			Conn: sc,
		})
	}

	// 创建 RTSP 连接
	sc.conn = conn.NewConn(sc.bc)

	// 创建 ServerConnReader
	cr := newServerConnReader(sc)

	err := sc.runInner()

	// 上下文取消
	sc.ctxCancel()

	// 关闭 TCP 连接
	sc.nconn.Close()

	cr.wait()

	if sc.session != nil {
		sc.session.removeConn(sc)
	}

	sc.s.closeConn(sc)

	// 判断 Server.Handler 是否实现了 ServerHandlerOnConnClose 接口，执行 OnConnClose() 回调
	if h, ok := sc.s.Handler.(ServerHandlerOnConnClose); ok {
		h.OnConnClose(&ServerHandlerOnConnCloseCtx{
			Conn:  sc,
			Error: err,
		})
	}
}

func (sc *ServerConn) runInner() error {
	for {
		select {
		case <-sc.ctx.Done(): // 上下文取消
			return liberrors.ErrServerTerminated{}

		case req := <-sc.chReadRequest: // 读取到 request
			// 阻塞等待处理完 RTSP 请求
			req.res <- sc.handleRequestOuter(req.req)

		case err := <-sc.chReadError: // 读取发生错误
			return err

		case ss := <-sc.chRemoveSession:
			if sc.session == ss {
				sc.session = nil
			}
		}
	}
}

func (sc *ServerConn) handleRequestInner(req *base.Request) (*base.Response, error) {
	if cseq, ok := req.Header["CSeq"]; !ok || len(cseq) != 1 {
		return &base.Response{
			StatusCode: base.StatusBadRequest,
			Header:     base.Header{},
		}, liberrors.ErrServerCSeqMissing{}
	}

	// 获取 SessionID
	sxID := getSessionID(req.Header)

	var path string
	var query string

	switch req.Method {
	case base.Describe, base.GetParameter, base.SetParameter:
		pathAndQuery, ok := req.URL.RTSPPathAndQuery()
		if !ok {
			return &base.Response{
				StatusCode: base.StatusBadRequest,
			}, liberrors.ErrServerInvalidPath{}
		}

		// 获取 URL 的 Path 和 Query 部分
		path, query = url.PathSplitQuery(pathAndQuery)
	}

	switch req.Method {
	case base.Options:
		if sxID != "" {
			return sc.handleRequestInSession(sxID, req, false)
		}

		var methods []string
		if _, ok := sc.s.Handler.(ServerHandlerOnDescribe); ok {
			methods = append(methods, string(base.Describe))
		}
		if _, ok := sc.s.Handler.(ServerHandlerOnAnnounce); ok {
			methods = append(methods, string(base.Announce))
		}
		if _, ok := sc.s.Handler.(ServerHandlerOnSetup); ok {
			methods = append(methods, string(base.Setup))
		}
		if _, ok := sc.s.Handler.(ServerHandlerOnPlay); ok {
			methods = append(methods, string(base.Play))
		}
		if _, ok := sc.s.Handler.(ServerHandlerOnRecord); ok {
			methods = append(methods, string(base.Record))
		}
		if _, ok := sc.s.Handler.(ServerHandlerOnPause); ok {
			methods = append(methods, string(base.Pause))
		}
		methods = append(methods, string(base.GetParameter))
		if _, ok := sc.s.Handler.(ServerHandlerOnSetParameter); ok {
			methods = append(methods, string(base.SetParameter))
		}
		methods = append(methods, string(base.Teardown))

		return &base.Response{
			StatusCode: base.StatusOK,
			Header: base.Header{
				"Public": base.HeaderValue{strings.Join(methods, ", ")},
			},
		}, nil

	case base.Describe:
		if h, ok := sc.s.Handler.(ServerHandlerOnDescribe); ok {
			res, stream, err := h.OnDescribe(&ServerHandlerOnDescribeCtx{
				Conn:    sc,
				Request: req,
				Path:    path,
				Query:   query,
			})

			if res.StatusCode == base.StatusOK {
				if res.Header == nil {
					res.Header = make(base.Header)
				}

				res.Header["Content-Base"] = base.HeaderValue{req.URL.String() + "/"}
				res.Header["Content-Type"] = base.HeaderValue{"application/sdp"}

				// VLC uses multicast if the SDP contains a multicast address.
				// therefore, we introduce a special query (vlcmulticast) that allows
				// to return a SDP that contains a multicast address.
				multicast := false
				if sc.s.MulticastIPRange != "" {
					if q, err := gourl.ParseQuery(query); err == nil {
						if _, ok := q["vlcmulticast"]; ok {
							multicast = true
						}
					}
				}

				if stream != nil {
					byts, _ := serverSideDescription(stream.desc, req.URL).Marshal(multicast)
					res.Body = byts
				}
			}

			return res, err
		}

	case base.Announce:
		if _, ok := sc.s.Handler.(ServerHandlerOnAnnounce); ok {
			return sc.handleRequestInSession(sxID, req, true)
		}

	case base.Setup:
		if _, ok := sc.s.Handler.(ServerHandlerOnSetup); ok {
			return sc.handleRequestInSession(sxID, req, true)
		}

	case base.Play:
		if sxID != "" {
			if _, ok := sc.s.Handler.(ServerHandlerOnPlay); ok {
				return sc.handleRequestInSession(sxID, req, false)
			}
		}

	case base.Record:
		if sxID != "" {
			if _, ok := sc.s.Handler.(ServerHandlerOnRecord); ok {
				return sc.handleRequestInSession(sxID, req, false)
			}
		}

	case base.Pause:
		if sxID != "" {
			if _, ok := sc.s.Handler.(ServerHandlerOnPause); ok {
				return sc.handleRequestInSession(sxID, req, false)
			}
		}

	case base.Teardown:
		if sxID != "" {
			return sc.handleRequestInSession(sxID, req, false)
		}

	case base.GetParameter:
		if sxID != "" {
			return sc.handleRequestInSession(sxID, req, false)
		}

		if h, ok := sc.s.Handler.(ServerHandlerOnGetParameter); ok {
			return h.OnGetParameter(&ServerHandlerOnGetParameterCtx{
				Conn:    sc,
				Request: req,
				Path:    path,
				Query:   query,
			})
		}

	case base.SetParameter:
		if sxID != "" {
			return sc.handleRequestInSession(sxID, req, false)
		}

		if h, ok := sc.s.Handler.(ServerHandlerOnSetParameter); ok {
			return h.OnSetParameter(&ServerHandlerOnSetParameterCtx{
				Conn:    sc,
				Request: req,
				Path:    path,
				Query:   query,
			})
		}
	}

	return &base.Response{
		StatusCode: base.StatusNotImplemented,
	}, nil
}

// handleRequestOuter -> handleRequestInner
func (sc *ServerConn) handleRequestOuter(req *base.Request) error {
	// 执行 Handler OnRequest 回调函数
	if h, ok := sc.s.Handler.(ServerHandlerOnRequest); ok {
		h.OnRequest(sc, req)
	}

	// 内部处理 request
	res, err := sc.handleRequestInner(req)

	if res.Header == nil {
		res.Header = make(base.Header)
	}

	// add cseq
	// 添加 CSeq Header
	if _, ok := err.(liberrors.ErrServerCSeqMissing); !ok {
		res.Header["CSeq"] = req.Header["CSeq"]
	}

	// add server
	// 添加 Server Header
	res.Header["Server"] = base.HeaderValue{"gortsplib"}

	// 执行 Handler OnResponse 回调函数
	if h, ok := sc.s.Handler.(ServerHandlerOnResponse); ok {
		h.OnResponse(sc, res)
	}

	// 设置写截止时间
	sc.nconn.SetWriteDeadline(time.Now().Add(sc.s.WriteTimeout))

	// 将响应写入网络连接
	err2 := sc.conn.WriteResponse(res)
	if err == nil && err2 != nil {
		err = err2
	}

	return err
}

func (sc *ServerConn) handleRequestInSession(
	sxID string,
	req *base.Request,
	create bool,
) (*base.Response, error) {
	// handle directly in Session
	if sc.session != nil {
		// session ID is optional in SETUP and ANNOUNCE requests, since
		// client may not have received the session ID yet due to multiple reasons:
		// * requests can be retries after code 301
		// * SETUP requests comes after ANNOUNCE response, that don't contain the session ID
		//
		// 会话 ID 在 SETUP 和 ANNOUNCE 请求中是可选的，因为客户端可能由于多种原因尚未收到会话 ID：
		// * 请求可以在代码 301 之后重试
		// * SETUP 请求在 ANNOUNCE 响应之后出现，不包含会话 ID
		if sxID != "" {
			// the connection can't communicate with two sessions at once.
			// 连接无法同时与两个会话通信。
			if sxID != sc.session.secretID {
				return &base.Response{
					StatusCode: base.StatusBadRequest,
				}, liberrors.ErrServerLinkedToOtherSession{}
			}
		}

		cres := make(chan sessionRequestRes)
		sreq := sessionRequestReq{
			sc:     sc,
			req:    req,
			id:     sxID,
			create: create,
			res:    cres,
		}

		res, session, err := sc.session.handleRequest(sreq)
		sc.session = session
		return res, err
	}

	// otherwise, pass through Server
	cres := make(chan sessionRequestRes)
	sreq := sessionRequestReq{
		sc:     sc,
		req:    req,
		id:     sxID,
		create: create,
		res:    cres,
	}

	res, session, err := sc.s.handleRequest(sreq)
	sc.session = session
	return res, err
}

func (sc *ServerConn) removeSession(ss *ServerSession) {
	select {
	case sc.chRemoveSession <- ss:
	case <-sc.ctx.Done():
	}
}

// 读取到 request
func (sc *ServerConn) readRequest(req readReq) error {
	select {
	case <-sc.ctx.Done(): // 上下文取消
		return liberrors.ErrServerTerminated{}

	case sc.chReadRequest <- req: // 从 tcp 连接中读取到 request
		// 阻塞等待响应
		return <-req.res

	}
}

// 读取发生错误
func (sc *ServerConn) readError(err error) {
	select {
	case <-sc.ctx.Done(): // 上下文取消

	case sc.chReadError <- err: // 从 tcp 连接中读取数据发生错误

	}
}
