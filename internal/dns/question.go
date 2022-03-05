package dns

import (
	"bytes"
	"encoding/binary"
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

// Question represents the question (i.e. query) to a name server. It has the
// following format:
//
//   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
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
	// Note that after compressing the domain name here, we also have to
	// uncompress it in Unpack!
	//
	// See: https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.4

	// To pack QName, process the domain name as a sequence of labels.
	labels := strings.Split(q.QName, ".")
	for _, label := range labels {
		// Each label must be encoded into:
		//  - A length byte; contains the length of the label (in bytes)
		//  - The label byte(s) itself
		err := binary.Write(buff, binary.BigEndian, byte(len(label)))
		if err != nil {
			return nil, err
		}
		err = binary.Write(buff, binary.BigEndian, []byte(label))
		if err != nil {
			return nil, err
		}
	}
	// A domain name terminates with the zero length byte (null label of root).
	err := binary.Write(buff, binary.BigEndian, byte(0))
	if err != nil {
		return nil, err
	}

	// Pack the remaining fields.
	err = binary.Write(buff, binary.BigEndian, q.QType)
	if err != nil {
		return nil, err
	}
	err = binary.Write(buff, binary.BigEndian, q.QClass)
	if err != nil {
		return nil, err
	}

	return buff.Bytes(), nil
}

// Unpack unpacks the DNS message question bytes (big-endian; network order).
// It returns either the unpacked byte count or an error.
func (q *Question) Unpack(msg []byte) (int, error) {
	off := 0

	// To unpack the QName, read the domain name labels one by one. Each label
	// will start with a length byte, followed by the actual label byte(s).
	labels := []string{}
	for {
		// Grab the length byte of the QName label, so we know its label size.
		lsize := int(msg[off])

		// QName always terminates with a zero length byte.
		if lsize == 0 {
			off += 1
			break
		}

		// The label byte(s) start after the length byte.
		start := off + 1
		label := string(msg[start : start+lsize])
		labels = append(labels, label)

		// Include the length byte to get the new offset.
		off += 1 + lsize
	}
	q.QName = strings.Join(labels, ".")

	// The QType and QClass are 2 sections of 16 bits each in the message.
	// To unpack each (remaining) section, left-shift the first byte to the "left
	// most" position, and OR it with the second byte to "merge" it back into a
	// single section of 16 bits.
	q.QType = QType(uint16(msg[off])<<8 | uint16(msg[off+1]))
	q.QClass = QClass(uint16(msg[off+2])<<8 | uint16(msg[off+3]))

	return len(msg), nil
}
