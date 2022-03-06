package dns

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// Msg represents a DNS communication message. It contains 5 sections, of which
// some can be empty.
//
// See: https://datatracker.ietf.org/doc/html/rfc1035#section-4.1
type Msg struct {
	// Header contains message information, and is always present.
	Header

	// Question describes the query to the name server.
	Question Question

	// Answer can be part of the response that contains resource records that
	// answer the question.
	Answer []RR

	// Authority can be part of the response that contains resource records that
	// point to an authoritative name server.
	Authority []RR

	// Additional can be part of the response that contains resource records with
	// additional information (also called "glue records").
	Additional []RR
}

// Pack packs the DNS message fields into binary format.
func (m *Msg) Pack() ([]byte, error) {
	buff := new(bytes.Buffer)

	hBytes, err := m.Header.Pack()
	if err != nil {
		return nil, fmt.Errorf("failed to pack dns message header: %v", err)
	}
	err = binary.Write(buff, binary.BigEndian, hBytes)
	if err != nil {
		return nil, err
	}

	qBytes, err := m.Question.Pack()
	if err != nil {
		return nil, fmt.Errorf("failed to pack dns message question: %v", err)
	}
	err = binary.Write(buff, binary.BigEndian, qBytes)
	if err != nil {
		return nil, err
	}

	return buff.Bytes(), nil
}

// Unpack unpacks the DNS message field bytes (big-endian; network order). It
// returns either the unpacked byte count or an error.
func (m *Msg) Unpack(msg []byte) (int, error) {
	off := 0

	hBytesRead, err := m.Header.Unpack(msg[0:12])
	if err != nil {
		return off, fmt.Errorf("failed to unpack dns message header: %v", err)
	}
	off += hBytesRead

	qBytesRead, err := m.Question.Unpack(msg[off:])
	if err != nil {
		return off, fmt.Errorf("failed to unpack dns message question: %v", err)
	}
	off += qBytesRead

	for i := 0; i < int(m.Header.ANCount); i++ {
		an := RR{}
		anBytesRead, err := an.Unpack(msg[off:])
		if err != nil {
			return off, fmt.Errorf(
				"failed to unpack dns message answer (%v): %v", i, err,
			)
		}
		m.Answer = append(m.Answer, an)
		off += anBytesRead
	}

	for i := 0; i < int(m.Header.NSCount); i++ {
		ns := RR{}
		nsBytesRead, err := ns.Unpack(msg[off:])
		if err != nil {
			return off, fmt.Errorf(
				"failed to unpack dns message authority (%v): %v", i, err,
			)
		}
		m.Authority = append(m.Authority, ns)
		off += nsBytesRead
	}

	for i := 0; i < int(m.Header.ARCount); i++ {
		ar := RR{}
		arBytesRead, err := ar.Unpack(msg[off:])
		if err != nil {
			return off, fmt.Errorf(
				"failed to unpack dns message additional (%v): %v", i, err,
			)
		}
		m.Additional = append(m.Additional, ar)
		off += arBytesRead
	}

	return off, nil
}
