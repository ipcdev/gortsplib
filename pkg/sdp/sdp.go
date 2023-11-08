// Package sdp contains a SDP encoder/decoder compatible with most RTSP implementations.
package sdp

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	psdp "github.com/pion/sdp/v3"
)

// SessionDescription is a SDP session description.
type SessionDescription psdp.SessionDescription

// Attribute returns the value of an attribute and if it exists
func (s *SessionDescription) Attribute(key string) (string, bool) {
	return (*psdp.SessionDescription)(s).Attribute(key)
}

// Marshal encodes a SessionDescription.
func (s *SessionDescription) Marshal() ([]byte, error) {
	return (*psdp.SessionDescription)(s).Marshal()
}

var (
	errSDPInvalidSyntax       = errors.New("sdp: invalid syntax")
	errSDPInvalidNumericValue = errors.New("sdp: invalid numeric value")
	errSDPInvalidValue        = errors.New("sdp: invalid value")
	errSDPInvalidPortValue    = errors.New("sdp: invalid port value")
)

func indexOf(element string, data []string) int {
	for k, v := range data {
		if element == v {
			return k
		}
	}
	return -1
}

func anyOf(element string, data ...string) bool {
	for _, v := range data {
		if element == v {
			return true
		}
	}
	return false
}

func parsePort(value string) (int, error) {
	port, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("%w `%v`", errSDPInvalidPortValue, port)
	}

	if port < 0 || port > 65536 {
		return 0, fmt.Errorf("%w -- out of range `%v`", errSDPInvalidPortValue, port)
	}

	return port, nil
}

// 反序列化 sdp协议版本号，如果不为 0 返回错误
func (s *SessionDescription) unmarshalProtocolVersion(value string) error {
	if value != "0" {
		return fmt.Errorf("invalid version")
	}

	return nil
}

// 会话名称
// 格式：s=
// 会话名称，在整个会话中有且只有1个 "s="
func (s *SessionDescription) unmarshalSessionName(value string) error {
	s.SessionName = psdp.SessionName(value)
	return nil
}

// 从字符串 s 从后向前反向索引字节 b
// 找到，返回字节 b 的索引下标；否则返回 -1
func stringsReverseIndexByte(s string, b byte) int {
	for i := len(s) - 2; i >= 0; i-- {
		if s[i] == b {
			return i
		}
	}
	return -1
}

// This is rewritten from scratch to make it compatible with most RTSP
// implementations.
// 这是从头开始重写的，以使其与大多数 RTSP 实现兼容。
//
// 格式：o=<username> <sessionid> <version> <network type> <address type> <address>
// 描述：o=选项 对会话的发起者进行了描述;
//
//		<username>：   是用户的登录名, 如果主机不支持 <username>，则用 "-" 代替，<username> 不能包含空格；
//		<session id>： 是一个数字串，在整个会话中，必须是唯一的，建议使用 NTP 时间戳;
//		<version>:     该会话公告的版本
//		<networktype>: 网络类型，一般为 "IN", 表示 internet
//		<addresstype>: 地址类型，一般为 IP4
//	    <adress>:      地址
//
// 示例：
// line:  o=- 0 0 IN IP4 127.0.0.1
// key:   o
// value: - 0 0 IN IP4 127.0.0.1
func (s *SessionDescription) unmarshalOrigin(value string) error {
	// 将入参中的 " IN IPV4 " 替换成 " IN IP4 "
	value = strings.Replace(value, " IN IPV4 ", " IN IP4 ", 1)

	// 判断 value 中是否有 " IN IP4 " 字符串
	i := strings.Index(value, " IN IP4 ")
	if i < 0 {
		// 如果没有，判断是否有 " IN IP6 " 字符串
		i = strings.Index(value, " IN IP6 ")
		if i < 0 {
			// 如果没有，返回错误
			return fmt.Errorf("%w `o=%v`", errSDPInvalidSyntax, value)
		}
	}

	// 网络类型：IN
	s.Origin.NetworkType = value[i+1 : i+3]
	// 地址类型：IP4
	s.Origin.AddressType = value[i+4 : i+7]
	// 单播地址：127.0.0.1
	s.Origin.UnicastAddress = strings.TrimSpace(value[i+8:])

	// 更新 value 为 "- 0 0"
	value = value[:i]

	// 从后向前遍历 value，返回 ' ' 的下标
	i = stringsReverseIndexByte(value, ' ')
	if i < 0 {
		return fmt.Errorf("%w `o=%v`", errSDPInvalidSyntax, value)
	}

	var tmp string
	// tmp  : "0"
	// value: "- 0"
	tmp, value = value[i+1:], value[:i]

	var err error

	switch {
	case strings.ContainsAny(tmp, "."):
		i := strings.Index(tmp, ".")
		s.Origin.SessionVersion, err = strconv.ParseUint(tmp[:i], 16, 64)
	default:
		// 会话版本号
		s.Origin.SessionVersion, err = strconv.ParseUint(tmp, 10, 64)
	}
	if err != nil {
		return fmt.Errorf("%w `%v`", errSDPInvalidNumericValue, tmp)
	}

	if value == "-0" { // live reporter app
		value = "- 0"
	}

	// value: "- 0"
	i = stringsReverseIndexByte(value, ' ')
	if i < 0 {
		return nil
	}

	// tmp  : 0
	// value: -
	tmp, value = value[i+1:], value[:i]

	switch {
	case strings.HasPrefix(tmp, "0x"), strings.HasPrefix(tmp, "0X"):
		s.Origin.SessionID, err = strconv.ParseUint(tmp[2:], 16, 64)
	case strings.ContainsAny(tmp, "abcdefABCDEF"):
		s.Origin.SessionID, err = strconv.ParseUint(tmp, 16, 64)
	case strings.ContainsAny(tmp, "."):
		i := strings.Index(tmp, ".")
		s.Origin.SessionID, err = strconv.ParseUint(tmp[:i], 16, 64)
	default:
		// SessionID
		s.Origin.SessionID, err = strconv.ParseUint(tmp, 10, 64)
	}
	if err != nil {
		return fmt.Errorf("%w `%v`", errSDPInvalidNumericValue, tmp)
	}

	// Username
	s.Origin.Username = value

	return nil
}

func (s *SessionDescription) unmarshalSessionInformation(value string) error {
	sessionInformation := psdp.Information(value)
	s.SessionInformation = &sessionInformation
	return nil
}

func (s *SessionDescription) unmarshalURI(value string) error {
	var err error
	s.URI, err = url.Parse(value)
	if err != nil {
		return err
	}

	return nil
}

func (s *SessionDescription) unmarshalEmail(value string) error {
	emailAddress := psdp.EmailAddress(value)
	s.EmailAddress = &emailAddress
	return nil
}

func (s *SessionDescription) unmarshalPhone(value string) error {
	phoneNumber := psdp.PhoneNumber(value)
	s.PhoneNumber = &phoneNumber
	return nil
}

func unmarshalConnectionInformation(value string) (*psdp.ConnectionInformation, error) {
	value = strings.Replace(value, "IN IPV4 ", "IN IP4 ", 1)

	if strings.HasPrefix(value, "IN c=IN") {
		value = value[len("IN c="):]
	}

	fields := strings.Fields(value)
	if len(fields) < 2 {
		return nil, fmt.Errorf("%w `c=%v`", errSDPInvalidSyntax, fields)
	}

	// Set according to currently registered with IANA
	// https://tools.ietf.org/html/rfc4566#section-8.2.6
	if i := indexOf(strings.ToUpper(fields[0]), []string{"IN"}); i == -1 {
		return nil, fmt.Errorf("%w `%v`", errSDPInvalidValue, fields[0])
	}

	// Set according to currently registered with IANA
	// https://tools.ietf.org/html/rfc4566#section-8.2.7
	if i := indexOf(fields[1], []string{"IP4", "IP6"}); i == -1 {
		return nil, fmt.Errorf("%w `%v`", errSDPInvalidValue, fields[1])
	}

	connAddr := new(psdp.Address)
	if len(fields) > 2 {
		connAddr.Address = fields[2]
	}

	return &psdp.ConnectionInformation{
		NetworkType: strings.ToUpper(fields[0]),
		AddressType: fields[1],
		Address:     connAddr,
	}, nil
}

// 格式： c=<networktype> <address type> <connection address>
// 描述：表示媒体连接信息；一个会话级描述中必须有 "c=" 或者 在每个媒体级描述中有一个 "c=" 选项，也可能在会话级描述和媒体级描述中都有 "c=" 选项；
//
//	<network type>：      表示网络类型，一般为 IN，表示 internet；
//	<address type>：      地址类型，一般为 IP4；
//	<connection address>：地址，可能为 域名 或 ip地址 两种形式
//
// 示例：c=IN IP4 172.17.133.211
func (s *SessionDescription) unmarshalSessionConnectionInformation(value string) error {
	var err error
	s.ConnectionInformation, err = unmarshalConnectionInformation(value)
	if err != nil {
		return fmt.Errorf("%w `c=%v`", errSDPInvalidSyntax, value)
	}

	return nil
}

func unmarshalBandwidth(value string) (*psdp.Bandwidth, error) {
	parts := strings.Split(value, ":")
	if len(parts) != 2 {
		return nil, fmt.Errorf("%w `b=%v`", errSDPInvalidValue, parts)
	}

	experimental := strings.HasPrefix(parts[0], "X-")
	if experimental {
		parts[0] = strings.TrimPrefix(parts[0], "X-")
	} else if !anyOf(parts[0], "CT", "AS", "TIAS", "RS", "RR") {
		// Set according to currently registered with IANA
		// https://tools.ietf.org/html/rfc4566#section-5.8
		// https://tools.ietf.org/html/rfc3890#section-6.2
		// https://tools.ietf.org/html/rfc3556#section-2
		return nil, fmt.Errorf("%w `%v`", errSDPInvalidValue, parts[0])
	}

	bandwidth, err := strconv.ParseUint(parts[1], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("%w `%v`", errSDPInvalidNumericValue, parts[1])
	}

	return &psdp.Bandwidth{
		Experimental: experimental,
		Type:         parts[0],
		Bandwidth:    bandwidth,
	}, nil
}

func (s *SessionDescription) unmarshalSessionBandwidth(value string) error {
	bandwidth, err := unmarshalBandwidth(value)
	if err != nil {
		return fmt.Errorf("%w `b=%v`", errSDPInvalidValue, value)
	}
	s.Bandwidth = append(s.Bandwidth, *bandwidth)

	return nil
}

func (s *SessionDescription) unmarshalTimeZones(value string) error {
	// These fields are transimitted in pairs
	// z=<adjustment time> <offset> <adjustment time> <offset> ....
	// so we are making sure that there are actually multiple of 2 total.
	fields := strings.Fields(value)
	if len(fields)%2 != 0 {
		return fmt.Errorf("%w `t=%v`", errSDPInvalidSyntax, fields)
	}

	for i := 0; i < len(fields); i += 2 {
		var timeZone psdp.TimeZone

		var err error
		timeZone.AdjustmentTime, err = strconv.ParseUint(fields[i], 10, 64)
		if err != nil {
			return fmt.Errorf("%w `%v`", errSDPInvalidValue, fields)
		}

		timeZone.Offset, err = parseTimeUnits(fields[i+1])
		if err != nil {
			return err
		}

		s.TimeZones = append(s.TimeZones, timeZone)
	}

	return nil
}

func (s *SessionDescription) unmarshalSessionEncryptionKey(value string) error {
	encryptionKey := psdp.EncryptionKey(value)
	s.EncryptionKey = &encryptionKey
	return nil
}

// 格式 ：a=<*>
// 描述：表示一个会话级别 或 媒体级别下的 0个或多个 属性
//
// 示例：
//
//	a=tool:libavformat 60.4.100
//	a=rtpmap:96 H264/90000
//	a=control:streamid=0
//	a=fmtp:97 profile-level-id=1;mode=AAC-hbr;sizelength=13;indexlength=3;indexdeltalength=3; config=1390
//	... ...
func (s *SessionDescription) unmarshalSessionAttribute(value string) error {
	// IndexRune()
	// 在一个 字符串 中从开始查找一个 中文 字符。
	// 函数返回 int 类型的值，如果包含，则返回第一次出现字符的索引；反之，则返回 -1。

	// 从 value 查找 : 字符
	i := strings.IndexRune(value, ':')

	var a psdp.Attribute
	if i > 0 { // 找到 : 字符
		// 使用 : 分隔 key、value
		a = psdp.NewAttribute(value[:i], value[i+1:])
	} else { // 没找到 : 字符
		// 将 value 作为 key
		a = psdp.NewPropertyAttribute(value)
	}

	s.Attributes = append(s.Attributes, a)

	return nil
}

// 格式：t=<start time> <stop time>
//
// 描述：t 字段描述了会话的 开始时间 和 结束时间
//
//	<start time> <stop time> 为 NTP 时间，单位是秒；
//	如果 <stop time> 为 0 表示过了 <start time> 之后，会话一直持续；
//	当 <start time> 和 <stop time> 都为 0 的时候，表示持久会话；
//
//	建议：两个值不设为 0，如果设为 0，不知道开始时间和结束时间，增大了调度的难度。
func (s *SessionDescription) unmarshalTiming(value string) error {
	if value == "now-" {
		// special case for some FLIR cameras with invalid timing element
		value = "0 0"
	}
	fields := strings.Fields(value)
	if len(fields) < 2 {
		return fmt.Errorf("%w `t=%v`", errSDPInvalidSyntax, fields)
	}

	td := psdp.TimeDescription{}

	var err error
	td.Timing.StartTime, err = strconv.ParseUint(fields[0], 10, 64)
	if err != nil {
		return fmt.Errorf("%w `%v`", errSDPInvalidNumericValue, fields[1])
	}

	td.Timing.StopTime, err = strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return fmt.Errorf("%w `%v`", errSDPInvalidNumericValue, fields[1])
	}

	s.TimeDescriptions = append(s.TimeDescriptions, td)

	return nil
}

func parseTimeUnits(value string) (int64, error) {
	// Some time offsets in the protocol can be provided with a shorthand
	// notation. This code ensures to convert it to NTP timestamp format.
	//      d - days (86400 seconds)
	//      h - hours (3600 seconds)
	//      m - minutes (60 seconds)
	//      s - seconds (allowed for completeness)
	switch value[len(value)-1:] {
	case "d":
		num, err := strconv.ParseInt(value[:len(value)-1], 10, 64)
		if err != nil {
			return 0, fmt.Errorf("%w `%v`", errSDPInvalidValue, value)
		}
		return num * 86400, nil
	case "h":
		num, err := strconv.ParseInt(value[:len(value)-1], 10, 64)
		if err != nil {
			return 0, fmt.Errorf("%w `%v`", errSDPInvalidValue, value)
		}
		return num * 3600, nil
	case "m":
		num, err := strconv.ParseInt(value[:len(value)-1], 10, 64)
		if err != nil {
			return 0, fmt.Errorf("%w `%v`", errSDPInvalidValue, value)
		}
		return num * 60, nil
	}

	num, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%w `%v`", errSDPInvalidValue, value)
	}

	return num, nil
}

func (s *SessionDescription) unmarshalRepeatTimes(value string) error {
	fields := strings.Fields(value)
	if len(fields) < 3 {
		return fmt.Errorf("%w `r=%v`", errSDPInvalidSyntax, value)
	}

	latestTimeDesc := &s.TimeDescriptions[len(s.TimeDescriptions)-1]

	newRepeatTime := psdp.RepeatTime{}
	var err error
	newRepeatTime.Interval, err = parseTimeUnits(fields[0])
	if err != nil {
		return fmt.Errorf("%w `%v`", errSDPInvalidValue, fields)
	}

	newRepeatTime.Duration, err = parseTimeUnits(fields[1])
	if err != nil {
		return fmt.Errorf("%w `%v`", errSDPInvalidValue, fields)
	}

	for i := 2; i < len(fields); i++ {
		offset, err := parseTimeUnits(fields[i])
		if err != nil {
			return fmt.Errorf("%w `%v`", errSDPInvalidValue, fields)
		}
		newRepeatTime.Offsets = append(newRepeatTime.Offsets, offset)
	}
	latestTimeDesc.RepeatTimes = append(latestTimeDesc.RepeatTimes, newRepeatTime)

	return nil
}

// 格式：m=<media> <port> <transport type> <fmt list>
//
// 描述：
//
//	 <media>：    表示媒体类型，有 "audio", "video", "application", "data"（不向用户显示的数据）, "control"（描述额外的控制通道）;
//	 <port>：     表示媒体流发往传输层的端口，对于 RTP，偶数端口用来传输数据，奇数端口用来;
//	 <transport>：表示传输协议，与 "c=" 一行相关联，
//	     一般用 RTP/AVP 表示，即 Realtime Transport Protocol using the Audio/Video profile over udp，即我们常说的 RTP over udp;
//	 <fmt list>：表示媒体格式，分为静态绑定和动态绑定
//		    静态绑定：媒体编码方式与 RTP 负载类型有确定的一一对应关系，如: m=audio 0 RTP/AVP 8
//		    动态绑定：媒体编码方式没有完全确定，需要使用 rtpmap 进行进一步的说明: 如：
//	            m=video 0 RTP/AVP 96
//		        a=rtpmap:96 H264/90000
//
// 示例：
func (s *SessionDescription) unmarshalMediaDescription(value string) error {
	fields := strings.Fields(value)
	if len(fields) < 4 {
		return fmt.Errorf("%w `m=%v`", errSDPInvalidSyntax, fields)
	}

	newMediaDesc := &psdp.MediaDescription{}

	// <media>
	// Set according to currently registered with IANA
	// https://tools.ietf.org/html/rfc4566#section-5.14
	if fields[0] != "video" &&
		fields[0] != "audio" &&
		fields[0] != "application" &&
		!strings.HasPrefix(fields[0], "application/") {
		return fmt.Errorf("%w `%v`", errSDPInvalidValue, fields[0])
	}
	newMediaDesc.MediaName.Media = fields[0]

	// <port>
	parts := strings.Split(fields[1], "/")
	var err error
	newMediaDesc.MediaName.Port.Value, err = parsePort(parts[0])
	if err != nil {
		return fmt.Errorf("%w `%v`", errSDPInvalidPortValue, parts[0])
	}

	if len(parts) > 1 {
		portRange, err := strconv.Atoi(parts[1])
		if err != nil {
			return fmt.Errorf("%w `%v`", errSDPInvalidValue, parts)
		}
		newMediaDesc.MediaName.Port.Range = &portRange
	}

	// <proto>
	// Set according to currently registered with IANA
	// https://tools.ietf.org/html/rfc4566#section-5.14
	for _, proto := range strings.Split(fields[2], "/") {
		if i := indexOf(proto, []string{
			"UDP", "RTP", "AVP", "SAVP", "SAVPF",
			"MP2T", "TLS", "DTLS", "SCTP", "AVPF", "TCP",
		}); i == -1 {
			return fmt.Errorf("%w `%v`", errSDPInvalidNumericValue, fields[2])
		}
		newMediaDesc.MediaName.Protos = append(newMediaDesc.MediaName.Protos, proto)
	}

	// <fmt>...
	for i := 3; i < len(fields); i++ {
		newMediaDesc.MediaName.Formats = append(newMediaDesc.MediaName.Formats, fields[i])
	}

	s.MediaDescriptions = append(s.MediaDescriptions, newMediaDesc)

	return nil
}

func (s *SessionDescription) unmarshalMediaTitle(value string) error {
	latestMediaDesc := s.MediaDescriptions[len(s.MediaDescriptions)-1]
	mediaTitle := psdp.Information(value)
	latestMediaDesc.MediaTitle = &mediaTitle
	return nil
}

func (s *SessionDescription) unmarshalMediaConnectionInformation(value string) error {
	latestMediaDesc := s.MediaDescriptions[len(s.MediaDescriptions)-1]
	var err error
	latestMediaDesc.ConnectionInformation, err = unmarshalConnectionInformation(value)
	if err != nil {
		return fmt.Errorf("%w `c=%v`", errSDPInvalidSyntax, value)
	}

	return nil
}

func (s *SessionDescription) unmarshalMediaBandwidth(value string) error {
	latestMediaDesc := s.MediaDescriptions[len(s.MediaDescriptions)-1]
	bandwidth, err := unmarshalBandwidth(value)
	if err != nil {
		return fmt.Errorf("%w `b=%v`", errSDPInvalidSyntax, value)
	}
	latestMediaDesc.Bandwidth = append(latestMediaDesc.Bandwidth, *bandwidth)
	return nil
}

func (s *SessionDescription) unmarshalMediaEncryptionKey(value string) error {
	latestMediaDesc := s.MediaDescriptions[len(s.MediaDescriptions)-1]
	encryptionKey := psdp.EncryptionKey(value)
	latestMediaDesc.EncryptionKey = &encryptionKey
	return nil
}

func (s *SessionDescription) unmarshalMediaAttribute(value string) error {
	i := strings.IndexRune(value, ':')
	var a psdp.Attribute
	if i > 0 {
		a = psdp.NewAttribute(value[:i], value[i+1:])
	} else {
		a = psdp.NewPropertyAttribute(value)
	}

	latestMediaDesc := s.MediaDescriptions[len(s.MediaDescriptions)-1]
	latestMediaDesc.Attributes = append(latestMediaDesc.Attributes, a)
	return nil
}

type unmarshalState int

const (
	stateInitial unmarshalState = iota
	stateSession
	stateMedia
	stateTimeDescription
)

// 反序列化 Session
func (s *SessionDescription) unmarshalSession(state *unmarshalState, key byte, val string) error {
	switch key {
	case 'o':
		// 反序列化源（o, Origin）
		err := s.unmarshalOrigin(val)
		if err != nil {
			return err
		}

	case 's':
		// 会话名称
		err := s.unmarshalSessionName(val)
		if err != nil {
			return err
		}

	case 'i':
		err := s.unmarshalSessionInformation(val)
		if err != nil {
			return err
		}

	case 'u':
		err := s.unmarshalURI(val)
		if err != nil {
			return err
		}

	case 'e':
		err := s.unmarshalEmail(val)
		if err != nil {
			return err
		}

	case 'p':
		err := s.unmarshalPhone(val)
		if err != nil {
			return err
		}

	case 'c':
		// 会话连接信息
		err := s.unmarshalSessionConnectionInformation(val)
		if err != nil {
			return err
		}

	case 'b':
		err := s.unmarshalSessionBandwidth(val)
		if err != nil {
			return err
		}

	case 'z':
		err := s.unmarshalTimeZones(val)
		if err != nil {
			return err
		}

	case 'k':
		err := s.unmarshalSessionEncryptionKey(val)
		if err != nil {
			return err
		}

	case 'a':
		// 会话属性
		err := s.unmarshalSessionAttribute(val)
		if err != nil {
			return err
		}

	case 't':
		// 会话开始、结束时间
		err := s.unmarshalTiming(val)
		if err != nil {
			return err
		}
		*state = stateTimeDescription

	case 'm':
		// 媒体描述
		err := s.unmarshalMediaDescription(val)
		if err != nil {
			return err
		}
		*state = stateMedia

	default:
		return fmt.Errorf("invalid key: %c", key)
	}

	return nil
}

func (s *SessionDescription) unmarshalMedia(key byte, val string) error {
	switch key {
	case 'm':
		err := s.unmarshalMediaDescription(val)
		if err != nil {
			return err
		}

	case 'i':
		err := s.unmarshalMediaTitle(val)
		if err != nil {
			return err
		}

	case 'c':
		err := s.unmarshalMediaConnectionInformation(val)
		if err != nil {
			return err
		}

	case 'b':
		err := s.unmarshalMediaBandwidth(val)
		if err != nil {
			return err
		}

	case 'k':
		err := s.unmarshalMediaEncryptionKey(val)
		if err != nil {
			return err
		}

	case 'a':
		err := s.unmarshalMediaAttribute(val)
		if err != nil {
			return err
		}

	default:
		return fmt.Errorf("invalid key: %c", key)
	}

	return nil
}

// Unmarshal decodes a SessionDescription.
// This is rewritten from scratch to guarantee compatibility with most RTSP
// implementations.
func (s *SessionDescription) Unmarshal(byts []byte) error {
	str := string(byts)

	state := stateInitial

	// 将 sdp 中的 \r 替换成 ""，并按照 \n 切分
	for _, line := range strings.Split(strings.ReplaceAll(str, "\r", ""), "\n") {
		if line == "" {
			continue
		}

		// 如果长度小于 2，或者第二个字符不是 =
		if len(line) < 2 || line[1] != '=' {
			return fmt.Errorf("invalid line: (%s)", line)
		}

		key := line[0]
		val := line[2:]

		switch state {
		case stateInitial:
			switch key {
			case 'v':
				// 处理 sdp 版本号
				err := s.unmarshalProtocolVersion(val)
				if err != nil {
					return err
				}

				// 更新状态为 stateSession
				state = stateSession

			default:
				state = stateSession
				err := s.unmarshalSession(&state, key, val)
				if err != nil {
					return err
				}
			}

		case stateSession:
			err := s.unmarshalSession(&state, key, val)
			if err != nil {
				return err
			}

		case stateMedia:
			err := s.unmarshalMedia(key, val)
			if err != nil {
				return err
			}

		case stateTimeDescription:
			switch key {
			case 'r':
				err := s.unmarshalRepeatTimes(val)
				if err != nil {
					return err
				}

			default:
				state = stateSession
				err := s.unmarshalSession(&state, key, val)
				if err != nil {
					return err
				}
			}
		}
	}

	return nil
}
