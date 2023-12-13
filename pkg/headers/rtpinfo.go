package headers

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/bluenviron/gortsplib/v4/pkg/base"
)

// RTPInfoEntry is an entry of a RTP-Info header.
// RTP-Info 头的条目
// 例如：
//
//	RTP-Info: url=rtsp://172.17.133.211:8554/mystream/trackID=0;seq=10873;rtptime=2426283273,url=rtsp://172.17.133.211:8554/mystream/trackID=1;seq=4809;rtptime=1578557208
type RTPInfoEntry struct {
	URL            string // media 的 URL
	SequenceNumber *uint16
	Timestamp      *uint32
}

// RTPInfo is a RTP-Info header.
type RTPInfo []*RTPInfoEntry

// Unmarshal decodes a RTP-Info header.
func (h *RTPInfo) Unmarshal(v base.HeaderValue) error {
	if len(v) == 0 {
		return fmt.Errorf("value not provided")
	}

	if len(v) > 1 {
		return fmt.Errorf("value provided multiple times (%v)", v)
	}

	for _, part := range strings.Split(v[0], ",") {
		e := &RTPInfoEntry{}

		// remove leading spaces
		part = strings.TrimLeft(part, " ")

		kvs, err := keyValParse(part, ';')
		if err != nil {
			return err
		}

		for k, v := range kvs {
			switch k {
			case "url":
				e.URL = v

			case "seq":
				vi, err := strconv.ParseUint(v, 10, 16)
				if err != nil {
					return err
				}
				vi2 := uint16(vi)
				e.SequenceNumber = &vi2

			case "rtptime":
				vi, err := strconv.ParseUint(v, 10, 32)
				if err != nil {
					return err
				}
				vi2 := uint32(vi)
				e.Timestamp = &vi2

			default:
				// ignore non-standard keys
			}
		}

		if e.URL == "" {
			return fmt.Errorf("URL is missing")
		}

		*h = append(*h, e)
	}

	return nil
}

// Marshal encodes a RTP-Info header.
// 编码为 RTP-Info 头
func (h RTPInfo) Marshal() base.HeaderValue {
	rets := make([]string, len(h))

	for i, e := range h {
		var tmp []string

		// url=rtsp://172.17.133.211:8554/mystream/trackID=0
		tmp = append(tmp, "url="+e.URL)

		if e.SequenceNumber != nil {
			// seq=10873
			tmp = append(tmp, "seq="+strconv.FormatUint(uint64(*e.SequenceNumber), 10))
		}

		if e.Timestamp != nil {
			// rtptime=2426283273
			tmp = append(tmp, "rtptime="+strconv.FormatUint(uint64(*e.Timestamp), 10))
		}

		// 将 url、seq、rtptime 使用 ";" 连接
		// url=rtsp://172.17.133.211:8554/mystream/trackID=0;seq=10873;rtptime=2426283273
		rets[i] = strings.Join(tmp, ";")
	}

	// 将多个 media 的 RTP-Info 使用 "," 连接
	// url=rtsp://172.17.133.211:8554/mystream/trackID=0;seq=10873;rtptime=2426283273,url=rtsp://172.17.133.211:8554/mystream/trackID=1;seq=4809;rtptime=1578557208
	return base.HeaderValue{strings.Join(rets, ",")}
}
