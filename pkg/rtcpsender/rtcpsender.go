// Package rtcpsender contains a utility to generate RTCP sender reports.
package rtcpsender

import (
	"sync"
	"time"

	"github.com/pion/rtcp"
	"github.com/pion/rtp"
)

// seconds since 1st January 1900
// higher 32 bits are the integer part, lower 32 bits are the fractional part
func ntpTimeGoToRTCP(v time.Time) uint64 {
	s := uint64(v.UnixNano()) + 2208988800*1000000000
	return (s/1000000000)<<32 | (s % 1000000000)
}

// RTCPSender is a utility to generate RTCP sender reports.
type RTCPSender struct {
	clockRate       float64           // 时钟频率
	period          time.Duration     // RTSP 服务器的 senderReportPeriod （默认值 10s）
	timeNow         func() time.Time  // 获取当前时间的函数
	writePacketRTCP func(rtcp.Packet) // 回调函数
	mutex           sync.RWMutex

	// data from RTP packets
	initialized        bool      // pts 等于 dts 时，置为 true
	lastTimeRTP        uint32    // pts 等于 dts 时，更新为 RTP 包的时间戳
	lastTimeNTP        time.Time // pts 等于 dts 时，更新
	lastTimeSystem     time.Time // pts 等于 dts 时，更新为 当前系统时间
	senderSSRC         uint32    // pts 等于 dts 时，更新 RTP 包的 SSRC
	lastSequenceNumber uint16    // 最后一个 RTP 包序号
	packetCount        uint32    // 累加统计处理的 RTP 包的数量
	octetCount         uint32    // 累加统计处理的 RTP 包负载字节数

	terminate chan struct{}
	done      chan struct{} // run() 协程退出时调用
}

// New allocates a RTCPSender.
//
//	参数：
//	- clockRate        时钟频率
//	- period           RTSP 服务器的 senderReportPeriod （默认值 10s）
//	- timeNow          获取当前时间的函数
//	- writePacketRTCP  回调函数
func New(
	clockRate int,
	period time.Duration,
	timeNow func() time.Time,
	writePacketRTCP func(rtcp.Packet),
) *RTCPSender {
	if timeNow == nil {
		timeNow = time.Now
	}

	rs := &RTCPSender{
		clockRate:       float64(clockRate),
		period:          period,
		timeNow:         timeNow,
		writePacketRTCP: writePacketRTCP,
		terminate:       make(chan struct{}),
		done:            make(chan struct{}),
	}

	go rs.run()

	return rs
}

// Close closes the RTCPSender.
func (rs *RTCPSender) Close() {
	close(rs.terminate)
	<-rs.done
}

func (rs *RTCPSender) run() {
	defer close(rs.done)

	// 创建定时器（每间隔 period 触发一次）
	t := time.NewTicker(rs.period)
	defer t.Stop()

	for {
		select {
		case <-t.C:
			report := rs.report()
			if report != nil {
				rs.writePacketRTCP(report)
			}

		case <-rs.terminate:
			return
		}
	}
}

func (rs *RTCPSender) report() rtcp.Packet {
	rs.mutex.Lock()
	defer rs.mutex.Unlock()

	if !rs.initialized {
		// initialized 为 false 时，返回 nil
		return nil
	}

	// 当前时间 - lastTimeSystem
	systemTimeDiff := rs.timeNow().Sub(rs.lastTimeSystem)
	// lastTimeNTP + systemTimeDiff
	ntpTime := rs.lastTimeNTP.Add(systemTimeDiff)
	// lastTimeRTP + systemTimeDiff.Seconds() * clockRate
	rtpTime := rs.lastTimeRTP + uint32(systemTimeDiff.Seconds()*rs.clockRate)

	return &rtcp.SenderReport{
		SSRC:        rs.senderSSRC,
		NTPTime:     ntpTimeGoToRTCP(ntpTime),
		RTPTime:     rtpTime,
		PacketCount: rs.packetCount,
		OctetCount:  rs.octetCount,
	}
}

// ProcessPacket extracts data from RTP packets.
// 处理 RTP 包，从 RTP 包中提取数据，并进行统计
//
// 参数：
//   - pkt            RTP 包
//   - ntp            ntp 时间戳
//   - ptsEqualsDTS   H.264 如果为负载 NALU 类型为 IDR、SPS、PPS，则为 true
func (rs *RTCPSender) ProcessPacket(pkt *rtp.Packet, ntp time.Time, ptsEqualsDTS bool) {
	rs.mutex.Lock()
	defer rs.mutex.Unlock()

	if ptsEqualsDTS {
		rs.initialized = true
		rs.lastTimeRTP = pkt.Timestamp
		rs.lastTimeNTP = ntp
		rs.lastTimeSystem = rs.timeNow()
		rs.senderSSRC = pkt.SSRC
	}

	rs.lastSequenceNumber = pkt.SequenceNumber

	rs.packetCount++
	rs.octetCount += uint32(len(pkt.Payload))
}

// SenderSSRC returns the SSRC of outgoing RTP packets.
func (rs *RTCPSender) SenderSSRC() (uint32, bool) {
	rs.mutex.RLock()
	defer rs.mutex.RUnlock()
	return rs.senderSSRC, rs.initialized
}

// LastPacketData returns metadata of the last RTP packet.
// 返回最后一个 RTP 包的元数据
func (rs *RTCPSender) LastPacketData() (uint16, uint32, time.Time, bool) {
	rs.mutex.RLock()
	defer rs.mutex.RUnlock()
	return rs.lastSequenceNumber, rs.lastTimeRTP, rs.lastTimeNTP, rs.initialized
}
