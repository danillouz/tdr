package dns

import (
	"bytes"
	"encoding/binary"
)

// OpCode represents a DNS operation code.
type OpCode byte

// String returns the string representation of an operation code.
func (oc OpCode) String() string {
	return OpCodeToString[oc]
}

const (
	// OpCodeQuery is a standard query.
	OpCodeQuery OpCode = iota

	// OpCodeIQuery is an inverse query.
	OpCodeIQuery

	// OpCodeStatus is a server status request.
	OpCodeStatus
)

// OpCodeToString maps an operation code to a string.
var OpCodeToString = map[OpCode]string{
	OpCodeQuery:  "QUERY",
	OpCodeIQuery: "IQUERY",
	OpCodeStatus: "STATUS",
}

// RCode represents a DNS response code.
type RCode byte

// String returns the string representation of a response code.
func (rc RCode) String() string {
	return RCodeToString[rc]
}

const (
	// RCodeNoError means there's no error condition.
	RCodeNoError RCode = iota

	// RCodeFormatError means the name server was unable to interpret the query.
	RCodeFormatError

	// RCodeServerFailure means the name server was unable to process the query
	// because of a problem with the name server.
	RCodeServerFailure

	// RCodeNameError means the domain name referenced in the query does not exist
	// (only relevant for responses from an authoritative name server).
	RCodeNameError

	// RCodeNotImplemented means the name server does not support the requested
	// type of query.
	RCodeNotImplemented

	// RCodeRefused means the name server refuses to perform the specified
	// operation.
	RCodeRefused
)

// OpCodeToString maps a response code to a string.
var RCodeToString = map[RCode]string{
	RCodeNoError:        "No Error",
	RCodeFormatError:    "Format Error",
	RCodeServerFailure:  "Server Failure",
	RCodeNameError:      "Name Error",
	RCodeNotImplemented: "Not Implemented",
	RCodeRefused:        "Refused",
}

// Header represents the DNS message header. It consists of 12 bytes with the
// following format:
//
//  15 14 13 12 11 10  9  8  7  6  5  4  3  2  1  0
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                      ID                       |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |QR|   OPCODE  |AA|TC|RD|RA|   Z    |   RCODE   |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    QDCOUNT                    |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    ANCOUNT                    |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    NSCOUNT                    |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    ARCOUNT                    |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//
// See: https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
type Header struct {
	// ID is the DNS message identifier. It is copied to the corresponding
	// response and can be used by the requester to match up replies to
	// outstanding queries.
	ID uint16

	// QR stands for Query or Response. This bit field specifies if the message
	// is a query (0) or response (1).
	QR byte

	// OpCode stands for Operation Code. This 4 bit field specifies what kind of
	// query the message is.
	OpCode OpCode

	// AA stands for Authoritative Answer. This bit field is valid in responses,
	// and specifies that the responding name server is an authority for the
	// domain name in the question section.
	AA byte

	// TC stands for TrunCation. This bit field specifies that this message was
	// truncated when its length is greater than permitted on the transmission channel.
	TC byte

	// RD stands for Recursion Desired. This bit field may be set in a query and
	// is copied into the response. If RD is set, it tells the name server to
	// resolve the query recursively.
	RD byte

	// RA stands for Recursion Available. This bit field is set or cleared in a
	// response, and specifies if the name server supports recursive queries.
	RA byte

	// Z is reserved for future use. It must be zero in all queries and responses.
	Z byte

	// RCode stands for Response Code. This 4 bit field is set as part of a
	// response.
	RCode RCode

	// QDCount specifies the number of entries in the question section.
	QDCount uint16

	// ANCount specifies the number of resource records in the answer section.
	ANCount uint16

	// NSCount specifies the number of name server resource records in the
	// authority section.
	NSCount uint16

	// ARCount specifies the number of resource records in the additional section.
	ARCount uint16
}

// Pack packs the DNS message header fields into binary format.
func (h *Header) Pack() ([]byte, error) {
	// The header fields must be packed into 6 sections of 16 bits (big endian),
	// where each section will be written into a single buffer.
	buff := new(bytes.Buffer)

	// First section: the ID is 16 bits, so just write it to the buffer.
	if err := binary.Write(buff, binary.BigEndian, h.ID); err != nil {
		return nil, err
	}

	// Second section: left-shift the bits of each field into the correct
	// position, and OR to "merge" all bits into a single section s.
	//
	//  15 14 13 12 11 10  9  8  7  6  5  4  3  2  1  0
	// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	// |QR|   OPCODE  |AA|TC|RD|RA|   Z    |   RCODE   |
	// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	var s uint16
	s |= uint16(h.QR) << 15
	s |= uint16(h.OpCode) << 11
	s |= uint16(h.AA) << 10
	s |= uint16(h.TC) << 9
	s |= uint16(h.RD) << 8
	s |= uint16(h.RA) << 7
	s |= uint16(h.RCode) << 0
	if err := binary.Write(buff, binary.BigEndian, s); err != nil {
		return nil, err
	}

	// Remaining sections: these take up 16 bits each, so just write them to the
	// buffer.
	if err := binary.Write(buff, binary.BigEndian, h.QDCount); err != nil {
		return nil, err
	}
	if err := binary.Write(buff, binary.BigEndian, h.ANCount); err != nil {
		return nil, err
	}
	if err := binary.Write(buff, binary.BigEndian, h.NSCount); err != nil {
		return nil, err
	}
	if err := binary.Write(buff, binary.BigEndian, h.ARCount); err != nil {
		return nil, err
	}

	return buff.Bytes(), nil
}

// Unpack unpacks the DNS message header field bytes (big-endian; network
// order). It returns either the unpacked byte count or an error.
func (h *Header) Unpack(msg []byte, off int) (int, error) {
	bytesRead := 0

	// The first 2 bytes contain the first section; ID.
	//
	// Left-shift the first byte to the "left most" position, and OR it with the
	// second byte to "merge" it back into a single section of 16 bits.
	h.ID = uint16(msg[off])<<8 | uint16(msg[off+1])
	bytesRead += 2

	// The 3rd and 4th bytes contain the second section.
	//
	//   7  6  5  4  3  2  1  0  7  6  5  4  3  2  1  0
	// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	// |QR|   OPCODE  |AA|TC|RD|RA|   Z    |   RCODE   |
	// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	//
	// To "query" the header's bit fields, for each bit field:
	// - Right-shift to the "right most" position, so only the queried bit field
	//   remains.
	// - Create a mask where all "left most" bits are "turned off", _except_ the
	//   bit(s) in the queried bit field (i.e. mask the length of the bit field).
	// - AND the header's shifted value with the mask to get the bit field value.
	h.QR = msg[off+2] >> 7 & queryByteMask(1)
	h.OpCode = OpCode(msg[off+2] >> 3 & queryByteMask(4))
	h.AA = msg[off+2] >> 2 & queryByteMask(1)
	h.TC = msg[off+2] >> 1 & queryByteMask(1)
	h.RD = msg[off+2] >> 0 & queryByteMask(1)
	h.RA = msg[off+3] >> 7 & queryByteMask(1)
	h.RCode = RCode(msg[off+3] >> 0 & queryByteMask(4))
	bytesRead += 2

	// The remaining bytes contain the remaining sections:
	// - The 5th and 6th bytes contain the third section; QDCOUNT.
	// - The 7th and 8th bytes contain the fourth section; ANCOUNT.
	// - The 9th and 10th bytes contain the fifth section; NSCOUNT.
	// - The 11th and 12th bytes contain the sixth section; ARCOUNT.
	//
	// Left-shift the first byte to the "left most" position, and OR it with the
	// second byte to "merge" it back into a single section of 16 bits.
	h.QDCount = uint16(msg[off+4])<<8 | uint16(msg[off+5])
	h.ANCount = uint16(msg[off+6])<<8 | uint16(msg[off+7])
	h.NSCount = uint16(msg[off+8])<<8 | uint16(msg[off+9])
	h.ARCount = uint16(msg[off+10])<<8 | uint16(msg[off+11])
	bytesRead += 8

	return bytesRead, nil
}
