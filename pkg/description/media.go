// Package description contains objects to describe streams.
package description

import (
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"

	psdp "github.com/pion/sdp/v3"

	"github.com/bluenviron/gortsplib/v4/pkg/format"
	"github.com/bluenviron/gortsplib/v4/pkg/url"
)

var smartRegexp = regexp.MustCompile("^([0-9]+) (.*?)/90000")

// 替换 Smart 负载类型
func replaceSmartPayloadType(payloadType string, attributes []psdp.Attribute) string {
	// 如果 payloadType 为 "smart/1/90000" ，
	// 遍历 sdp format 中的属性，查找 key "rtpmap"，正则匹配 value，
	// 如果匹配，则返回 sm[1]
	//
	// 否则，返回 payloadType
	//
	if payloadType == "smart/1/90000" {
		for _, attr := range attributes {
			if attr.Key == "rtpmap" {
				sm := smartRegexp.FindStringSubmatch(attr.Value)
				if sm != nil {
					return sm[1]
				}
			}
		}
	}
	return payloadType
}

// 遍历 SDP 属性，查找给定 key 对应的 value。
// 如果没有找到，返回空字符串
func getAttribute(attributes []psdp.Attribute, key string) string {
	for _, attr := range attributes {
		if attr.Key == key {
			return attr.Value
		}
	}
	return ""
}

// 遍历 sdp 属性，查找 key 为 （sendonly | recvonly | sendrecv）的属性。
// 如果未找到，返回空字符串
func getDirection(attributes []psdp.Attribute) MediaDirection {
	for _, attr := range attributes {
		switch attr.Key {
		case "sendonly":
			return MediaDirectionSendonly

		case "recvonly":
			return MediaDirectionRecvonly

		case "sendrecv":
			return MediaDirectionSendrecv
		}
	}
	return ""
}

// 获取 Format 属性
//   - attributes  sdp format 中的属性
//   - payloadType 负载类型
//   - key         要查找的属性的 key
func getFormatAttribute(attributes []psdp.Attribute, payloadType uint8, key string) string {
	for _, attr := range attributes {
		// 判断是否与要找的 key 相等
		if attr.Key == key {
			// 去除空格
			v := strings.TrimSpace(attr.Value)

			// 使用 ' ' 将 value 切分为两部分
			if parts := strings.SplitN(v, " ", 2); len(parts) == 2 {
				// 将 parts[0] 以 十进制 进行解析，解析后的值类型为 uint8
				// 如果 parts[0] 等于 payloadType，则返回 parts[1]
				if tmp, err := strconv.ParseUint(parts[0], 10, 8); err == nil && uint8(tmp) == payloadType {
					return parts[1]
				}
			}
		}
	}

	// 否则返回空字符串
	return ""
}

// 解码 FMTP
// 例如：fmtp:96 packetization-mode=1; profile-level-id=42E01E; sprop-parameter-sets=J0LgHqkYFAX/LgDUGAQa2wrXvfAQ,KN4JyA==
// 则 enc 为：packetization-mode=1; profile-level-id=42E01E; sprop-parameter-sets=J0LgHqkYFAX/LgDUGAQa2wrXvfAQ,KN4JyA==
func decodeFMTP(enc string) map[string]string {
	// 参数校验
	if enc == "" {
		return nil
	}

	ret := make(map[string]string)

	// 使用 ; 进行切分，得到以下值：
	//  - packetization-mode=1
	//  - profile-level-id=42E01E
	//  - sprop-parameter-sets=J0LgHqkYFAX/LgDUGAQa2wrXvfAQ,KN4JyA==
	for _, kv := range strings.Split(enc, ";") {
		// 去除空格
		kv = strings.Trim(kv, " ")

		if len(kv) == 0 {
			continue
		}

		// 使用 = 切分为两部分
		tmp := strings.SplitN(kv, "=", 2)
		if len(tmp) != 2 {
			continue
		}

		ret[strings.ToLower(tmp[0])] = tmp[1]
	}

	return ret
}

func sortedKeys(fmtp map[string]string) []string {
	keys := make([]string, len(fmtp))
	i := 0
	for key := range fmtp {
		keys[i] = key
		i++
	}
	sort.Strings(keys)
	return keys
}

// 判断 v 是否为数字
func isAlphaNumeric(v string) bool {
	for _, r := range v {
		if !unicode.IsLetter(r) && !unicode.IsNumber(r) {
			return false
		}
	}
	return true
}

// MediaDirection is the direction of a media stream.
// MediaDirection 是媒体流的方向。
type MediaDirection string

// standard directions.
// 标准方向
const (
	MediaDirectionSendonly MediaDirection = "sendonly" // 仅发送
	MediaDirectionRecvonly MediaDirection = "recvonly" // 仅接收
	MediaDirectionSendrecv MediaDirection = "sendrecv" // 发送接收
)

// MediaType is the type of a media stream.
// 媒体流类型
type MediaType string

// standard media stream types.
// 标准媒体流类型
const (
	MediaTypeVideo       MediaType = "video"
	MediaTypeAudio       MediaType = "audio"
	MediaTypeApplication MediaType = "application"
)

// Media is a media stream.
// It contains one or more formats.
// Media 是媒体流。解析 SDP 格式得到
// 它包含一种或多种格式。???
type Media struct {
	// Media type.
	// 媒体类型
	Type MediaType

	// Media ID (optional).
	// 媒体 ID （可选）
	ID string

	// Direction of the stream (optional).
	// 流的方向（可选）。
	Direction MediaDirection

	// Control attribute.
	// 控制属性
	Control string

	// Formats contained into the media.
	// 媒体中包含的格式。
	Formats []format.Format
}

// Unmarshal decodes the media from the SDP format.
// 从 SDP 媒体描述中解码得到 media。
func (m *Media) Unmarshal(md *psdp.MediaDescription) error {
	// 报文中的源数据：
	// m=video 0 RTP/AVP 96
	// m=audio 0 RTP/AVP 97

	// 获取媒体的类型
	m.Type = MediaType(md.MediaName.Media)

	// 从 SDP 中获取 mid 属性
	m.ID = getAttribute(md.Attributes, "mid")

	// 如果 ID 不为空，但是不是数字，返回 error
	if m.ID != "" && !isAlphaNumeric(m.ID) {
		return fmt.Errorf("invalid mid: %v", m.ID)
	}

	// 获取方向属性
	// key 为：sendonly、recvonly、sendrecv
	m.Direction = getDirection(md.Attributes)

	// 报文中源数据：
	//      a=control:streamid=0
	//      a=control:streamid=1
	//
	// 获取属性 control
	m.Control = getAttribute(md.Attributes, "control")

	m.Formats = nil
	for _, payloadType := range md.MediaName.Formats {
		// 负载类型
		payloadType = replaceSmartPayloadType(payloadType, md.Attributes)

		// 将 payloadType 以 十进制 解析，转换后的值类型为 uint8
		tmp, err := strconv.ParseUint(payloadType, 10, 8)
		if err != nil {
			return err
		}
		payloadTypeInt := uint8(tmp)

		// 获取 rtpmap
		rtpMap := getFormatAttribute(md.Attributes, payloadTypeInt, "rtpmap")
		// 获取 fmtp，并进行解码
		fmtp := decodeFMTP(getFormatAttribute(md.Attributes, payloadTypeInt, "fmtp"))

		// 获取媒体格式 Format
		format, err := format.Unmarshal(string(m.Type), payloadTypeInt, rtpMap, fmtp)
		if err != nil {
			return err
		}

		m.Formats = append(m.Formats, format)
	}

	if m.Formats == nil {
		return fmt.Errorf("no formats found")
	}

	return nil
}

// Marshal encodes the media in SDP format.
// 编码 Media 为 SDP 格式
func (m Media) Marshal() *psdp.MediaDescription {
	md := &psdp.MediaDescription{
		MediaName: psdp.MediaName{
			Media:  string(m.Type),
			Protos: []string{"RTP", "AVP"},
		},
	}

	if m.ID != "" {
		md.Attributes = append(md.Attributes, psdp.Attribute{
			Key:   "mid",
			Value: m.ID,
		})
	}

	if m.Direction != "" {
		md.Attributes = append(md.Attributes, psdp.Attribute{
			Key: string(m.Direction),
		})
	}

	md.Attributes = append(md.Attributes, psdp.Attribute{
		Key:   "control",
		Value: m.Control,
	})

	for _, forma := range m.Formats {
		typ := strconv.FormatUint(uint64(forma.PayloadType()), 10)
		md.MediaName.Formats = append(md.MediaName.Formats, typ)

		rtpmap := forma.RTPMap()
		if rtpmap != "" {
			md.Attributes = append(md.Attributes, psdp.Attribute{
				Key:   "rtpmap",
				Value: typ + " " + rtpmap,
			})
		}

		fmtp := forma.FMTP()
		if len(fmtp) != 0 {
			tmp := make([]string, len(fmtp))
			for i, key := range sortedKeys(fmtp) {
				tmp[i] = key + "=" + fmtp[key]
			}

			md.Attributes = append(md.Attributes, psdp.Attribute{
				Key:   "fmtp",
				Value: typ + " " + strings.Join(tmp, "; "),
			})
		}
	}

	return md
}

// URL returns the absolute URL of the media.
// 返回 media 的绝对路径
func (m Media) URL(contentBase *url.URL) (*url.URL, error) {
	if contentBase == nil {
		return nil, fmt.Errorf("Content-Base header not provided")
	}

	// no control attribute, use base URL
	// 没有 control 属性，使用 base URL
	if m.Control == "" {
		return contentBase, nil
	}

	// control attribute contains an absolute path
	if strings.HasPrefix(m.Control, "rtsp://") ||
		strings.HasPrefix(m.Control, "rtsps://") {
		ur, err := url.Parse(m.Control)
		if err != nil {
			return nil, err
		}

		// copy host and credentials
		ur.Host = contentBase.Host
		ur.User = contentBase.User
		return ur, nil
	}

	// control attribute contains a relative control attribute
	// insert the control attribute at the end of the URL
	// if there's a query, insert it after the query
	// otherwise insert it after the path
	//
	// control 属性包含相对控制属性
	// 在 URL 末尾插入 control 属性，如果有 query，则将其插入在 query 之后，否则将其插入在路径之后
	strURL := contentBase.String()
	// 如果 control 属性第一个字节不为 ?，且 strURL 结尾不为 /
	// 则在 strURL 后加 / 字符
	if m.Control[0] != '?' && !strings.HasSuffix(strURL, "/") {
		strURL += "/"
	}

	ur, _ := url.Parse(strURL + m.Control)
	return ur, nil
}

// FindFormat finds a certain format among all the formats in the media.
// 在媒体的所有格式中查找某种格式。
func (m Media) FindFormat(forma interface{}) bool {
	for _, formak := range m.Formats {
		if reflect.TypeOf(formak) == reflect.TypeOf(forma).Elem() {
			reflect.ValueOf(forma).Elem().Set(reflect.ValueOf(formak))
			return true
		}
	}
	return false
}
