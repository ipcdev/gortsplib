package gortsplib

import (
	"github.com/bluenviron/gortsplib/v4/pkg/description"
)

type serverStreamMedia struct {
	st              *ServerStream                 // RTSP 流
	media           *description.Media            // RTSP 流内的一个 media
	trackID         int                           // media 对应的轨道 ID
	formats         map[uint8]*serverStreamFormat // media 负载的格式（key：负载类型    value：Format）
	multicastWriter *serverMulticastWriter
}

// 创建 serverStreamMedia
// 参数：
//   - st       ServerStream 代表一条 RTSP 流
//   - medi     代表 RTSP 流内的一个媒体
//   - trackID  轨道 ID 号
func newServerStreamMedia(st *ServerStream, medi *description.Media, trackID int) *serverStreamMedia {
	sm := &serverStreamMedia{
		st:      st,
		media:   medi,
		trackID: trackID,
	}

	sm.formats = make(map[uint8]*serverStreamFormat)
	for _, forma := range medi.Formats {
		sm.formats[forma.PayloadType()] = newServerStreamFormat(
			sm,
			forma)
	}

	return sm
}

func (sm *serverStreamMedia) close() {
	for _, tr := range sm.formats {
		if tr.rtcpSender != nil {
			tr.rtcpSender.Close()
		}
	}

	if sm.multicastWriter != nil {
		sm.multicastWriter.close()
	}
}

// 发送一个 RTCP 包给 RTSP 流的所有 reader
func (sm *serverStreamMedia) writePacketRTCP(byts []byte) error {
	// send unicast
	for r := range sm.st.activeUnicastReaders {
		sm, ok := r.setuppedMedias[sm.media]
		if ok {
			err := sm.writePacketRTCP(byts)
			if err != nil {
				r.onStreamWriteError(err)
			}
		}
	}

	// send multicast
	if sm.multicastWriter != nil {
		err := sm.multicastWriter.writePacketRTCP(byts)
		if err != nil {
			return err
		}
	}

	return nil
}
