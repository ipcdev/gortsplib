package description

import (
	"fmt"
	"strings"

	psdp "github.com/pion/sdp/v3"

	"github.com/bluenviron/gortsplib/v4/pkg/sdp"
	"github.com/bluenviron/gortsplib/v4/pkg/url"
)

func atLeastOneHasMID(medias []*Media) bool {
	for _, media := range medias {
		if media.ID != "" {
			return true
		}
	}
	return false
}

func atLeastOneDoesntHaveMID(medias []*Media) bool {
	for _, media := range medias {
		if media.ID == "" {
			return true
		}
	}
	return false
}

func hasMediaWithID(medias []*Media, id string) bool {
	for _, media := range medias {
		if media.ID == id {
			return true
		}
	}
	return false
}

// SessionFECGroup is a FEC group.
type SessionFECGroup []string

// Session is the description of a RTSP stream.
// Session 是一个 RTSP 流的描述
//
// 一个 RTSP 流有一个 URL，
// 一个 RTSP 流内包含多个 "媒体流" （Audio/Video）
type Session struct {
	// Base URL of the stream (read only).
	BaseURL *url.URL

	// Title of the stream (optional).
	// 使用 SDP 的 session name 填充（SDP 中的 s=No Name）
	Title string

	// FEC groups (RFC5109).
	FECGroups []SessionFECGroup

	// Media streams.
	Medias []*Media
}

// FindFormat finds a certain format among all the formats in all the medias of the stream.
// If the format is found, it is inserted into forma, and its media is returned.
//
// 在 RTSP 流的所有 medias 的所有 formats 中查找某种 format。
// 如果找到该格式，并返回其媒体。
func (d *Session) FindFormat(forma interface{}) *Media {
	for _, media := range d.Medias {
		ok := media.FindFormat(forma)
		if ok {
			return media
		}
	}
	return nil
}

// Unmarshal decodes the description from SDP.
// 从 SDP Session 描述中解码得到 Session
func (d *Session) Unmarshal(ssd *sdp.SessionDescription) error {
	// 会话名
	d.Title = string(ssd.SessionName)
	if d.Title == " " {
		d.Title = ""
	}

	d.Medias = make([]*Media, len(ssd.MediaDescriptions))

	for i, md := range ssd.MediaDescriptions {
		var m Media
		err := m.Unmarshal(md)
		if err != nil {
			return fmt.Errorf("media %d is invalid: %v", i+1, err)
		}

		if m.ID != "" && hasMediaWithID(d.Medias[:i], m.ID) {
			return fmt.Errorf("duplicate media IDs")
		}

		d.Medias[i] = &m
	}

	if atLeastOneHasMID(d.Medias) && atLeastOneDoesntHaveMID(d.Medias) {
		return fmt.Errorf("media IDs sent partially")
	}

	for _, attr := range ssd.Attributes {
		if attr.Key == "group" && strings.HasPrefix(attr.Value, "FEC ") {
			group := SessionFECGroup(strings.Split(attr.Value[len("FEC "):], " "))

			for _, id := range group {
				if !hasMediaWithID(d.Medias, id) {
					return fmt.Errorf("FEC group points to an invalid media ID: %v", id)
				}
			}

			d.FECGroups = append(d.FECGroups, group)
		}
	}

	return nil
}

// Marshal encodes the description in SDP.
// 编码 RTSP 流描述为 SDP 格式。
func (d Session) Marshal(multicast bool) ([]byte, error) {
	var sessionName psdp.SessionName
	if d.Title != "" {
		sessionName = psdp.SessionName(d.Title)
	} else {
		// RFC 4566: If a session has no meaningful name, the
		// value "s= " SHOULD be used (i.e., a single space as the session name).
		sessionName = psdp.SessionName(" ")
	}

	var address string
	if multicast {
		address = "224.1.0.0"
	} else {
		address = "0.0.0.0"
	}

	sout := &sdp.SessionDescription{
		SessionName: sessionName,
		Origin: psdp.Origin{
			Username:       "-",
			NetworkType:    "IN",
			AddressType:    "IP4",
			UnicastAddress: "127.0.0.1",
		},
		// required by Darwin Sessioning Server
		ConnectionInformation: &psdp.ConnectionInformation{
			NetworkType: "IN",
			AddressType: "IP4",
			Address:     &psdp.Address{Address: address},
		},
		TimeDescriptions: []psdp.TimeDescription{
			{Timing: psdp.Timing{StartTime: 0, StopTime: 0}},
		},
		MediaDescriptions: make([]*psdp.MediaDescription, len(d.Medias)),
	}

	for i, media := range d.Medias {
		sout.MediaDescriptions[i] = media.Marshal()
	}

	for _, group := range d.FECGroups {
		sout.Attributes = append(sout.Attributes, psdp.Attribute{
			Key:   "group",
			Value: "FEC " + strings.Join(group, " "),
		})
	}

	return sout.Marshal()
}
