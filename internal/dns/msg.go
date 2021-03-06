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

// SetQuery sets the required header- and question fields to send a DNS message
// query.
func (m *Msg) SetQuery(name string, qt QType) error {
	id, err := generateMsgID()
	if err != nil {
		return fmt.Errorf("failed to generate message ID: %v", err)
	}

	m.ID = id
	m.QR = 0
	m.OpCode = OpCodeQuery
	m.RD = 1
	m.QDCount = 1
	m.Question = Question{
		QName:  name,
		QType:  qt,
		QClass: ClassIN,
	}

	return nil
}

// Pack packs the DNS message fields into binary format.
func (m *Msg) Pack() ([]byte, error) {
	buff := new(bytes.Buffer)

	hBytes, err := m.Header.Pack()
	if err != nil {
		return nil, fmt.Errorf("failed to pack header: %v", err)
	}
	if err := binary.Write(buff, binary.BigEndian, hBytes); err != nil {
		return nil, err
	}

	qBytes, err := m.Question.Pack()
	if err != nil {
		return nil, fmt.Errorf("failed to pack question: %v", err)
	}
	if err := binary.Write(buff, binary.BigEndian, qBytes); err != nil {
		return nil, err
	}

	return buff.Bytes(), nil
}

// Unpack unpacks the DNS message field bytes (big-endian; network order). It
// returns either the unpacked byte count or an error.
func (m *Msg) Unpack(msg []byte) (int, error) {
	off := 0

	n, err := m.Header.Unpack(msg, off)
	if err != nil {
		return off, fmt.Errorf("failed to unpack header: %v", err)
	}
	off += n

	n, err = m.Question.Unpack(msg, off)
	if err != nil {
		return off, fmt.Errorf("failed to unpack question: %v", err)
	}
	off += n

	for i := 0; i < int(m.Header.ANCount); i++ {
		an := RR{}
		n, err := an.Unpack(msg, off)
		if err != nil {
			return off, fmt.Errorf("failed to unpack answer (%v): %v", i, err)
		}
		m.Answer = append(m.Answer, an)
		off += n
	}

	for i := 0; i < int(m.Header.NSCount); i++ {
		ns := RR{}
		n, err := ns.Unpack(msg, off)
		if err != nil {
			return off, fmt.Errorf("failed to unpack  authority (%v): %v", i, err)
		}
		m.Authority = append(m.Authority, ns)
		off += n
	}

	for i := 0; i < int(m.Header.ARCount); i++ {
		ar := RR{}
		n, err := ar.Unpack(msg, off)
		if err != nil {
			return off, fmt.Errorf("failed to unpack additional (%v): %v", i, err)
		}
		m.Additional = append(m.Additional, ar)
		off += n
	}

	return off, nil
}
