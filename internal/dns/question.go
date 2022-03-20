package dns

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
)

// QType fields appear in the question section of a DNS query. QType values are
// a superset of Types, so every Type is a valid QType.
//
// See: https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.3
type QType = Type

// QClass fields appear in the question section of a DNS query. QClass values
// are a superset of Class values, so every Class is a valid QClass.
//
// See: https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.5
type QClass = Class

// Question represents the DNS question (i.e. query) to a name server. It has
// the following format:
//
//  15 14 13 12 11 10  9  8  7  6  5  4  3  2  1  0
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                                               |
// /                     QNAME                     /
// /                                               /
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                     QTYPE                     |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                     QCLASS                    |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//
// See: https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.2
type Question struct {
	// QName is a domain name represented as a sequence of labels. This field may
	// be an odd number of bytes; no padding is used.
	QName string

	// QType is a two byte code which specifies the type of the query.
	QType QType

	// QClass is a two byte code that specifies the class of the query.
	QClass QClass
}

// Pack packs the DNS message question fields into binary format.
func (q *Question) Pack() ([]byte, error) {
	buff := new(bytes.Buffer)

	// TODO: compress the domain name to reduce message size.
	//
	// Per RFC 1035 this is not required for sending messages, but doing so will
	// increase datagram capacity.
	//
	// See: https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.4

	// To pack QName, process the domain name as a sequence of labels.
	labels := strings.Split(q.QName, ".")
	for _, label := range labels {
		// Root label "." is split as an empty string.
		if label == "" {
			break
		}

		// Each label must be encoded into:
		//  - A length byte; contains the length of the label (in bytes)
		//  - The label byte(s) itself
		if err := binary.Write(buff, binary.BigEndian, byte(len(label))); err != nil {
			return nil, err
		}
		if err := binary.Write(buff, binary.BigEndian, []byte(label)); err != nil {
			return nil, err
		}
	}

	// A domain name terminates with the zero length byte (null label of root).
	if err := binary.Write(buff, binary.BigEndian, byte(0)); err != nil {
		return nil, err
	}

	// Pack the remaining fields.
	if err := binary.Write(buff, binary.BigEndian, q.QType); err != nil {
		return nil, err
	}
	if err := binary.Write(buff, binary.BigEndian, q.QClass); err != nil {
		return nil, err
	}

	return buff.Bytes(), nil
}

// Unpack unpacks the DNS message question bytes (big-endian; network order).
// It returns either the unpacked byte count or an error.
func (q *Question) Unpack(msg []byte, off int) (int, error) {
	bytesRead := 0

	name, offn, n := unpackDomainName(msg, off)
	q.QName = name
	off = offn
	bytesRead += n

	// The QType and QClass are 2 sections of 2 bytes each.
	// To unpack each (remaining) section, left-shift the first byte to the "left
	// most" position, and OR it with the second byte to "merge" it back into a
	// single section of 2 bytes.
	q.QType = QType(uint16(msg[off])<<8 | uint16(msg[off+1]))
	q.QClass = QClass(uint16(msg[off+2])<<8 | uint16(msg[off+3]))
	bytesRead += 4

	return bytesRead, nil
}

// String returns a "dig like" string representation of the question.
func (q *Question) String() string {
	return fmt.Sprintf(
		"%s\t%s\t%s",
		q.QName, q.QClass, q.QType,
	)
}
