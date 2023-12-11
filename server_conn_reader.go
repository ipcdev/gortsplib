package gortsplib

import (
	"sync/atomic"
	"time"

	"github.com/bluenviron/gortsplib/v4/pkg/base"
	"github.com/bluenviron/gortsplib/v4/pkg/liberrors"
)

type errSwitchReadFunc struct {
	tcp bool
}

func (errSwitchReadFunc) Error() string {
	return "switching read function"
}

func isErrSwitchReadFunc(err error) bool {
	_, ok := err.(errSwitchReadFunc)
	return ok
}

// 封装 ServerConn，使用 conn.Conn 从 TCP 连接中读取数据，判断出数据的类型（request、response、interleaved frame）
type serverConnReader struct {
	sc *ServerConn

	chReadDone chan struct{}
}

func newServerConnReader(sc *ServerConn) *serverConnReader {
	cr := &serverConnReader{
		sc:         sc,
		chReadDone: make(chan struct{}),
	}

	go cr.run()

	return cr
}

// 等待 serverConnReader 退出
func (cr *serverConnReader) wait() {
	<-cr.chReadDone
}

func (cr *serverConnReader) run() {
	defer close(cr.chReadDone)

	// 初始化读函数
	readFunc := cr.readFuncStandard

	// for 循环不断执行读函数
	for {
		err := readFunc()
		if err, ok := err.(errSwitchReadFunc); ok {
			// 进行读函数的切换
			// 什么情况下会发生读函数的切换？
			if err.tcp {
				readFunc = cr.readFuncTCP
			} else {
				readFunc = cr.readFuncStandard
			}
			continue
		}

		// 发生 非 errSwitchReadFunc 类型的错误
		cr.sc.readError(err)
		break
	}
}

func (cr *serverConnReader) readFuncStandard() error {
	// reset deadline
	// 重置 TCP 连接的读截止时间
	cr.sc.nconn.SetReadDeadline(time.Time{})

	for {
		// 使用 conn.Conn 读取数据
		what, err := cr.sc.conn.Read()
		if err != nil {
			return err
		}

		// 判断读取到的数据的类型
		// Standard 方式读，RTSP 服务端只处理 request，不会处理 response、interleaved frame
		switch what := what.(type) {
		case *base.Request:
			cres := make(chan error)
			req := readReq{req: what, res: cres}
			err := cr.sc.readRequest(req)
			if err != nil {
				return err
			}

		case *base.Response:
			return liberrors.ErrServerUnexpectedResponse{}

		case *base.InterleavedFrame:
			return liberrors.ErrServerUnexpectedFrame{}
		}
	}
}

func (cr *serverConnReader) readFuncTCP() error {
	// reset deadline
	cr.sc.nconn.SetReadDeadline(time.Time{})

	cr.sc.session.startWriter()

	for {
		if cr.sc.session.state == ServerSessionStateRecord {
			cr.sc.nconn.SetReadDeadline(time.Now().Add(cr.sc.s.ReadTimeout))
		}

		what, err := cr.sc.conn.Read()
		if err != nil {
			return err
		}

		switch what := what.(type) {
		case *base.Request:
			cres := make(chan error)
			req := readReq{req: what, res: cres}
			err := cr.sc.readRequest(req)
			if err != nil {
				return err
			}

		case *base.Response:
			return liberrors.ErrServerUnexpectedResponse{}

		case *base.InterleavedFrame:
			atomic.AddUint64(cr.sc.session.bytesReceived, uint64(len(what.Payload)))

			if cb, ok := cr.sc.session.tcpCallbackByChannel[what.Channel]; ok {
				cb(what.Payload)
			}
		}
	}
}
