package gortsplib

import (
	"sync"
	"time"

	"github.com/pion/rtcp"
	"github.com/pion/rtp"

	"github.com/bluenviron/gortsplib/v4/pkg/description"
	"github.com/bluenviron/gortsplib/v4/pkg/headers"
	"github.com/bluenviron/gortsplib/v4/pkg/liberrors"
)

// 第一个 Format
func firstFormat(formats map[uint8]*serverStreamFormat) *serverStreamFormat {
	var firstKey uint8
	for key := range formats {
		firstKey = key
		break
	}

	return formats[firstKey]
}

// ServerStream represents a data stream.
// This is in charge of
// - distributing the stream to each reader
// - allocating multicast listeners
// - gathering infos about the stream in order to generate SSRC and RTP-Info
//
// ServerStream 代表一个数据流。
// 负责：
//   - 将 stream 分发给每个 reader
//   - 分配 多播 listeners
//   - 收集有关流的信息以生成 SSRC 和 RTP-Info
type ServerStream struct {
	s    *Server              // RTSP 服务器
	desc *description.Session // RTSP 流的描述

	mutex                sync.RWMutex
	readers              map[*ServerSession]struct{}
	multicastReaderCount int
	activeUnicastReaders map[*ServerSession]struct{} // 活跃的 单播 reader
	streamMedias         map[*description.Media]*serverStreamMedia
	closed               bool // RTSP 流是否关闭
}

// NewServerStream allocates a ServerStream.
// 创建一个 RTSP 流
func NewServerStream(s *Server, desc *description.Session) *ServerStream {
	st := &ServerStream{
		s:                    s,
		desc:                 desc,
		readers:              make(map[*ServerSession]struct{}),
		activeUnicastReaders: make(map[*ServerSession]struct{}),
	}

	// 初始化 map
	st.streamMedias = make(map[*description.Media]*serverStreamMedia, len(desc.Medias))

	for i, medi := range desc.Medias {
		// 创建 streamMedia
		st.streamMedias[medi] = newServerStreamMedia(st, medi, i)
	}

	return st
}

// Close closes a ServerStream.
func (st *ServerStream) Close() {
	st.mutex.Lock()
	st.closed = true
	st.mutex.Unlock()

	for ss := range st.readers {
		ss.Close()
	}

	for _, sm := range st.streamMedias {
		sm.close()
	}
}

// Description returns the description of the stream.
func (st *ServerStream) Description() *description.Session {
	return st.desc
}

func (st *ServerStream) senderSSRC(medi *description.Media) (uint32, bool) {
	st.mutex.Lock()
	defer st.mutex.Unlock()

	sm := st.streamMedias[medi]

	// senderSSRC() is used to fill SSRC inside the Transport header.
	// if there are multiple formats inside a single media stream,
	// do not return anything, since Transport headers don't support multiple SSRCs.
	//
	// senderSSRC() 用于填充传输标头内的 SSRC。
	// 如果单个媒体流中有多种格式，则不返回任何内容，因为传输标头不支持多个 SSRC。
	if len(sm.formats) > 1 {
		return 0, false
	}

	return firstFormat(sm.formats).rtcpSender.SenderSSRC()
}

func (st *ServerStream) rtpInfoEntry(medi *description.Media, now time.Time) *headers.RTPInfoEntry {
	st.mutex.Lock()
	defer st.mutex.Unlock()

	sm := st.streamMedias[medi]

	// if there are multiple formats inside a single media stream,
	// do not generate a RTP-Info entry, since RTP-Info doesn't support
	// multiple sequence numbers / timestamps.
	if len(sm.formats) > 1 {
		return nil
	}

	format := firstFormat(sm.formats)

	lastSeqNum, lastTimeRTP, lastTimeNTP, ok := format.rtcpSender.LastPacketData()
	if !ok {
		return nil
	}

	clockRate := format.format.ClockRate()
	if clockRate == 0 {
		return nil
	}

	// sequence number of the first packet of the stream
	seqNum := lastSeqNum + 1

	// RTP timestamp corresponding to the time value in
	// the Range response header.
	// remove a small quantity in order to avoid DTS > PTS
	ts := uint32(uint64(lastTimeRTP) +
		uint64(now.Sub(lastTimeNTP).Seconds()*float64(clockRate)) -
		uint64(clockRate)/10)

	return &headers.RTPInfoEntry{
		SequenceNumber: &seqNum,
		Timestamp:      &ts,
	}
}

func (st *ServerStream) readerAdd(
	ss *ServerSession,
	clientPorts *[2]int,
) error {
	st.mutex.Lock()
	defer st.mutex.Unlock()

	if st.closed {
		return liberrors.ErrServerStreamClosed{}
	}

	switch *ss.setuppedTransport {
	case TransportUDP:
		// check whether UDP ports and IP are already assigned to another reader
		for r := range st.readers {
			if *r.setuppedTransport == TransportUDP &&
				r.author.ip().Equal(ss.author.ip()) &&
				r.author.zone() == ss.author.zone() {
				for _, rt := range r.setuppedMedias {
					if rt.udpRTPReadPort == clientPorts[0] {
						return liberrors.ErrServerUDPPortsAlreadyInUse{Port: rt.udpRTPReadPort}
					}
				}
			}
		}

	case TransportUDPMulticast:
		if st.multicastReaderCount == 0 {
			for _, media := range st.streamMedias {
				mh, err := newServerMulticastWriter(st.s)
				if err != nil {
					return err
				}
				media.multicastWriter = mh
			}
		}
		st.multicastReaderCount++
	}

	st.readers[ss] = struct{}{}

	return nil
}

func (st *ServerStream) readerRemove(ss *ServerSession) {
	st.mutex.Lock()
	defer st.mutex.Unlock()

	if st.closed {
		return
	}

	delete(st.readers, ss)

	if *ss.setuppedTransport == TransportUDPMulticast {
		st.multicastReaderCount--
		if st.multicastReaderCount == 0 {
			for _, media := range st.streamMedias {
				media.multicastWriter.close()
				media.multicastWriter = nil
			}
		}
	}
}

// 设置 reader 为 Active
func (st *ServerStream) readerSetActive(ss *ServerSession) {
	st.mutex.Lock()
	defer st.mutex.Unlock()

	if st.closed {
		return
	}

	if *ss.setuppedTransport == TransportUDPMulticast {
		for medi, sm := range ss.setuppedMedias {
			streamMedia := st.streamMedias[medi]
			streamMedia.multicastWriter.rtcpl.addClient(
				ss.author.ip(), streamMedia.multicastWriter.rtcpl.port(), sm.readRTCPUDPPlay)
		}
	} else {
		st.activeUnicastReaders[ss] = struct{}{}
	}
}

func (st *ServerStream) readerSetInactive(ss *ServerSession) {
	st.mutex.Lock()
	defer st.mutex.Unlock()

	if st.closed {
		return
	}

	if *ss.setuppedTransport == TransportUDPMulticast {
		for medi := range ss.setuppedMedias {
			streamMedia := st.streamMedias[medi]
			streamMedia.multicastWriter.rtcpl.removeClient(ss.author.ip(), streamMedia.multicastWriter.rtcpl.port())
		}
	} else {
		delete(st.activeUnicastReaders, ss)
	}
}

// WritePacketRTP writes a RTP packet to all the readers of the stream.
func (st *ServerStream) WritePacketRTP(medi *description.Media, pkt *rtp.Packet) error {
	return st.WritePacketRTPWithNTP(medi, pkt, st.s.timeNow())
}

// WritePacketRTPWithNTP writes a RTP packet to all the readers of the stream.
// ntp is the absolute time of the packet, and is sent with periodic RTCP sender reports.
func (st *ServerStream) WritePacketRTPWithNTP(medi *description.Media, pkt *rtp.Packet, ntp time.Time) error {
	byts := make([]byte, st.s.MaxPacketSize)
	n, err := pkt.MarshalTo(byts)
	if err != nil {
		return err
	}
	byts = byts[:n]

	st.mutex.RLock()
	defer st.mutex.RUnlock()

	if st.closed {
		return liberrors.ErrServerStreamClosed{}
	}

	sm := st.streamMedias[medi]
	sf := sm.formats[pkt.PayloadType]
	return sf.writePacketRTP(byts, pkt, ntp)
}

// WritePacketRTCP writes a RTCP packet to all the readers of the stream.
// 发送一个 RTCP 包给 RTSP 流的所有 reader
func (st *ServerStream) WritePacketRTCP(medi *description.Media, pkt rtcp.Packet) error {
	// RTCP 包序列化为字节数组
	byts, err := pkt.Marshal()
	if err != nil {
		return err
	}

	st.mutex.RLock()
	defer st.mutex.RUnlock()

	// 检查 RTSP 流是否关闭
	if st.closed {
		return liberrors.ErrServerStreamClosed{}
	}

	sm := st.streamMedias[medi]
	return sm.writePacketRTCP(byts)
}
