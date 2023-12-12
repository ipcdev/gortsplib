// Package format contains RTP format definitions, decoders and encoders.
package format

import (
	"strings"

	"github.com/pion/rtp"
)

// 解析 rtpMap，获取 Codec 与 Clock
func getCodecAndClock(rtpMap string) (string, string) {
	// 使用 / 将 rtpMap 切分为两部分
	parts2 := strings.SplitN(rtpMap, "/", 2)
	if len(parts2) != 2 {
		return "", ""
	}

	return strings.ToLower(parts2[0]), parts2[1]
}

// 反序列化上下文
type unmarshalContext struct {
	mediaType   string            // 媒体类型（例如 video）
	payloadType uint8             // 负载类型（例如 96）
	clock       string            // clock（从 rtpMap 解析得到， 例如 H264）
	codec       string            // codec（从 rtpMap 解析得到， 例如 90000）
	rtpMap      string            // rtpMap（例如 H264/90000）
	fmtp        map[string]string // fmtp
}

// Format is a media format.
// It defines the payload type of RTP packets and how to encode/decode them.
// Format 是一种媒体格式。
// 它定义了 RTP 数据包的有效负载类型以及如何对其进行编码/解码。
type Format interface {
	unmarshal(ctx *unmarshalContext) error

	// Codec returns the codec name.
	Codec() string

	// ClockRate returns the clock rate.
	ClockRate() int

	// PayloadType returns the payload type.
	PayloadType() uint8

	// RTPMap returns the rtpmap attribute.
	RTPMap() string

	// FMTP returns the fmtp attribute.
	FMTP() map[string]string

	// PTSEqualsDTS checks whether PTS is equal to DTS in RTP packets.
	PTSEqualsDTS(*rtp.Packet) bool
}

// Unmarshal decodes a format from a media description.
// 从 media 描述中解码一个 Format
//
// 参数：
//   - mediaType    媒体类型 （audio/video/application）
//   - payloadType  媒体负载类型
//   - rtpMap       包含 Codec 与 Clock 信息
//   - fmtp
func Unmarshal(mediaType string, payloadType uint8, rtpMap string, fmtp map[string]string) (Format, error) {
	// 解析 rtpMap 获取 Codec 与 Clock
	codec, clock := getCodecAndClock(rtpMap)

	// 根据 codec、clock 返回对应的 Format
	format := func() Format {
		switch {
		// video

		case codec == "av1" && clock == "90000":
			return &AV1{}

		case codec == "vp9" && clock == "90000":
			return &VP9{}

		case codec == "vp8" && clock == "90000":
			return &VP8{}

		case codec == "h265" && clock == "90000":
			return &H265{}

		case codec == "h264" && clock == "90000":
			return &H264{}

		case codec == "mp4v-es" && clock == "90000":
			return &MPEG4Video{}

		case payloadType == 32:
			return &MPEG1Video{}

		case payloadType == 26:
			return &MJPEG{}

		case payloadType == 33:
			return &MPEGTS{}

		// audio

		case codec == "opus":
			return &Opus{}

		case codec == "vorbis":
			return &Vorbis{}

		case codec == "mpeg4-generic", codec == "mp4a-latm":
			return &MPEG4Audio{}

		case payloadType == 14:
			return &MPEG1Audio{}

		case codec == "ac3":
			return &AC3{}

		case codec == "speex":
			return &Speex{}

		case (codec == "g726-16" ||
			codec == "g726-24" ||
			codec == "g726-32" ||
			codec == "g726-40" ||
			codec == "aal2-g726-16" ||
			codec == "aal2-g726-24" ||
			codec == "aal2-g726-32" ||
			codec == "aal2-g726-40") && clock == "8000":
			return &G726{}

		case payloadType == 9:
			return &G722{}

		case payloadType == 0, payloadType == 8:
			return &G711{}

		case codec == "l8", codec == "l16", codec == "l24":
			return &LPCM{}
		}

		return &Generic{}
	}()

	// 交给对用的 Format 实例进行反序列化
	err := format.unmarshal(&unmarshalContext{
		mediaType:   mediaType,
		payloadType: payloadType,
		clock:       clock,
		codec:       codec,
		rtpMap:      rtpMap,
		fmtp:        fmtp,
	})
	if err != nil {
		return nil, err
	}

	return format, nil
}
