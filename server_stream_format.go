package gortsplib

import (
	"time"

	"github.com/pion/rtcp"
	"github.com/pion/rtp"

	"github.com/bluenviron/gortsplib/v4/pkg/format"
	"github.com/bluenviron/gortsplib/v4/pkg/rtcpsender"
)

type serverStreamFormat struct {
	sm         *serverStreamMedia // RTSP 流内的一个 media
	format     format.Format      // media 负载的格式
	rtcpSender *rtcpsender.RTCPSender
}

func newServerStreamFormat(sm *serverStreamMedia, forma format.Format) *serverStreamFormat {
	sf := &serverStreamFormat{
		sm:     sm,
		format: forma,
	}

	// 创建 RTCP Sender
	sf.rtcpSender = rtcpsender.New(
		forma.ClockRate(),
		sm.st.s.senderReportPeriod,
		sm.st.s.timeNow,
		func(pkt rtcp.Packet) {
			if !sm.st.s.DisableRTCPSenderReports {
				// DisableRTCPSenderReports：false （既启用 RTCP Sender 发送 Report）
				sm.st.WritePacketRTCP(sm.media, pkt) //nolint:errcheck
			}
		},
	)

	return sf
}

func (sf *serverStreamFormat) writePacketRTP(byts []byte, pkt *rtp.Packet, ntp time.Time) error {
	sf.rtcpSender.ProcessPacket(pkt, ntp, sf.format.PTSEqualsDTS(pkt))

	// send unicast
	for r := range sf.sm.st.activeUnicastReaders {
		sm, ok := r.setuppedMedias[sf.sm.media]
		if ok {
			err := sm.writePacketRTP(byts)
			if err != nil {
				r.onStreamWriteError(err)
			}
		}
	}

	// send multicast
	if sf.sm.multicastWriter != nil {
		err := sf.sm.multicastWriter.writePacketRTP(byts)
		if err != nil {
			return err
		}
	}

	return nil
}
