package format

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/pion/rtp"

	"github.com/bluenviron/gortsplib/v4/pkg/format/rtph264"
	"github.com/bluenviron/mediacommon/pkg/codecs/h264"
)

// H264 is a RTP format for the H264 codec.
// Specification: https://datatracker.ietf.org/doc/html/rfc6184
type H264 struct {
	PayloadTyp        uint8  // 负载类型
	SPS               []byte // 解析 fmtp 得到的 SPS
	PPS               []byte // 解析 fmtp 得到的 PPS
	PacketizationMode int    // 打包模式

	mutex sync.RWMutex
}

func (f *H264) unmarshal(ctx *unmarshalContext) error {
	f.PayloadTyp = ctx.payloadType

	// 遍历 fmtp
	//  - packetization-mode    :  1
	//  - profile-level-id      :  42E01E
	//  - sprop-parameter-sets  :  J0LgHqkYFAX/LgDUGAQa2wrXvfAQ,KN4JyA==
	for key, val := range ctx.fmtp {
		switch key {
		case "sprop-parameter-sets":
			// 使用 , 切分
			tmp := strings.Split(val, ",")
			if len(tmp) >= 2 {
				// base64 解码 tmp[0]，得到 sps
				sps, err := base64.StdEncoding.DecodeString(tmp[0])
				if err != nil {
					return fmt.Errorf("invalid sprop-parameter-sets (%v)", val)
				}

				// some cameras ship parameters with Annex-B prefix
				// 某些相机附带的参数带有 Annex-B 前缀
				// 如果有，去掉前缀
				sps = bytes.TrimPrefix(sps, []byte{0, 0, 0, 1})

				// base64 解码 tmp[1]，得到 pps
				pps, err := base64.StdEncoding.DecodeString(tmp[1])
				if err != nil {
					return fmt.Errorf("invalid sprop-parameter-sets (%v)", val)
				}

				// some cameras ship parameters with Annex-B prefix
				// 某些相机附带的参数带有 Annex-B 前缀
				// 如果有，去掉前缀
				pps = bytes.TrimPrefix(pps, []byte{0, 0, 0, 1})

				// 验证 SPS 是否合法
				var spsp h264.SPS
				err = spsp.Unmarshal(sps)
				if err != nil {
					continue
				}

				f.SPS = sps
				f.PPS = pps
			}

		case "packetization-mode":
			// 按十进制进行解析 val
			tmp, err := strconv.ParseUint(val, 10, 31)
			if err != nil {
				return fmt.Errorf("invalid packetization-mode (%v)", val)
			}

			f.PacketizationMode = int(tmp)
		}
	}

	return nil
}

// Codec implements Format.
func (f *H264) Codec() string {
	return "H264"
}

// ClockRate implements Format.
func (f *H264) ClockRate() int {
	return 90000
}

// PayloadType implements Format.
func (f *H264) PayloadType() uint8 {
	return f.PayloadTyp
}

// RTPMap implements Format.
func (f *H264) RTPMap() string {
	return "H264/90000"
}

// FMTP implements Format.
func (f *H264) FMTP() map[string]string {
	f.mutex.RLock()
	defer f.mutex.RUnlock()

	fmtp := make(map[string]string)

	if f.PacketizationMode != 0 {
		fmtp["packetization-mode"] = strconv.FormatInt(int64(f.PacketizationMode), 10)
	}

	var tmp []string
	if f.SPS != nil {
		tmp = append(tmp, base64.StdEncoding.EncodeToString(f.SPS))
	}
	if f.PPS != nil {
		tmp = append(tmp, base64.StdEncoding.EncodeToString(f.PPS))
	}
	if tmp != nil {
		fmtp["sprop-parameter-sets"] = strings.Join(tmp, ",")
	}
	if len(f.SPS) >= 4 {
		fmtp["profile-level-id"] = strings.ToUpper(hex.EncodeToString(f.SPS[1:4]))
	}

	return fmtp
}

// PTSEqualsDTS implements Format.
func (f *H264) PTSEqualsDTS(pkt *rtp.Packet) bool {
	// PTS 与 DTS 是否相等
	// 如果为 IDR、SPS、PPS，返回 true

	//  RTP 包的负载为 0，返回 false
	if len(pkt.Payload) == 0 {
		return false
	}

	// NALU 类型（RTP 包负载第一个字节 & 0x1F）
	typ := h264.NALUType(pkt.Payload[0] & 0x1F)

	switch typ {
	case h264.NALUTypeIDR, h264.NALUTypeSPS, h264.NALUTypePPS:
		// 如果为 IDR、SPS、PPS，返回 true
		return true

	case 24: // STAP-A
		payload := pkt.Payload[1:]

		for len(payload) > 0 {
			if len(payload) < 2 {
				// 剩余 payload 长度 小于 2，返回 false
				return false
			}

			// 前两个字节代表 数据的长度
			size := uint16(payload[0])<<8 | uint16(payload[1])
			payload = payload[2:]

			if size == 0 || int(size) > len(payload) {
				// 如果 size 为 0，或者 size 大于 剩余负载的长度，返回 false
				return false
			}

			var nalu []byte
			nalu, payload = payload[:size], payload[size:]

			typ = h264.NALUType(nalu[0] & 0x1F)
			switch typ {
			case h264.NALUTypeIDR, h264.NALUTypeSPS, h264.NALUTypePPS:
				// 如果为 IDR、SPS、PPS，返回 true
				return true
			}
		}

	case 28: // FU-A
		if len(pkt.Payload) < 2 {
			// 如果负载的长度小于 2，返回 false
			return false
		}

		// payload 第二个字节 右移 7 位，
		// 如果不等于 1 ，返回 false
		start := pkt.Payload[1] >> 7
		if start != 1 {
			return false
		}

		typ := h264.NALUType(pkt.Payload[1] & 0x1F)
		switch typ {
		case h264.NALUTypeIDR, h264.NALUTypeSPS, h264.NALUTypePPS:
			// 如果为 IDR、SPS、PPS，返回 true
			return true
		}
	}

	return false
}

// CreateDecoder creates a decoder able to decode the content of the format.
func (f *H264) CreateDecoder() (*rtph264.Decoder, error) {
	d := &rtph264.Decoder{
		PacketizationMode: f.PacketizationMode,
	}

	err := d.Init()
	if err != nil {
		return nil, err
	}

	return d, nil
}

// CreateEncoder creates an encoder able to encode the content of the format.
func (f *H264) CreateEncoder() (*rtph264.Encoder, error) {
	e := &rtph264.Encoder{
		PayloadType:       f.PayloadTyp,
		PacketizationMode: f.PacketizationMode,
	}

	err := e.Init()
	if err != nil {
		return nil, err
	}

	return e, nil
}

// SafeSetParams sets the codec parameters.
func (f *H264) SafeSetParams(sps []byte, pps []byte) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	f.SPS = sps
	f.PPS = pps
}

// SafeParams returns the codec parameters.
func (f *H264) SafeParams() ([]byte, []byte) {
	f.mutex.RLock()
	defer f.mutex.RUnlock()
	return f.SPS, f.PPS
}
