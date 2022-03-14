package dns

import (
	"fmt"
	"net"
)

// Type represents a resource record type.
//
// See: https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.2
type Type uint16

const (
	TypeUnknown Type = iota

	// TypeA is a host address (i.e. IP address).
	TypeA

	// TypeNS is an authoritative name server.
	TypeNS

	// TypeMD is a mail destination (Obsolete: use MX).
	TypeMD

	// TypeMF is a mail forwarder (Obsolete: use MX).
	TypeMF

	// TypeCNAME is the canonical name for an alias.
	TypeCNAME

	// TypeSOA marks the start of a zone of authority.
	TypeSOA

	// TypeMB is a mailbox domain name (experimental).
	TypeMB

	// TypeMG is a mail group member (experimental).
	TypeMG

	// TypeMR is a mail rename domain name (experimental).
	TypeMR

	// TypeNULL is a null resource record (experimental).
	TypeNULL

	// TypeWKS is a well known service description.
	TypeWKS

	// TypePTR is a domain name pointer.
	TypePTR

	// TypeHINFO is host information.
	TypeHINFO

	// TypeMINFO is mailbox or mail list information.
	TypeMINFO

	// TypeMX is mail exchange.
	TypeMX

	// TypeTXT is text strings.
	TypeTXT
)

// TypeToString maps a resource record type to a string.
var TypeToString = map[Type]string{
	TypeA:     "A",
	TypeNS:    "NS",
	TypeMD:    "MD",
	TypeMF:    "MF",
	TypeCNAME: "CNAME",
	TypeSOA:   "SOA",
	TypeMB:    "MB",
	TypeMG:    "MG",
	TypeMR:    "MR",
	TypeNULL:  "NULL",
	TypeWKS:   "WKS",
	TypePTR:   "PTR",
	TypeHINFO: "HINFO",
	TypeMINFO: "MINFO",
	TypeMX:    "MX",
	TypeTXT:   "TXT",
}

// Class represents a resource record class.
//
// See: https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.4
type Class uint16

const (
	ClassUnknown Class = iota

	// ClassIN stands for the internet.
	ClassIN
)

// ClassToString maps a resource record type to a string.
var ClassToString = map[Class]string{
	ClassIN: "IN",
}

// RR represents a resource record. The message answer, authority, and
// additional sections all share the same format: a variable number of resource
// records, where the number of records is specified in the corresponding count
// field in the message header. Each resource record has the following format:
//
//  15 14 13 12 11 10  9  8  7  6  5  4  3  2  1  0
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                                               |
// /                                               /
// /                      NAME                     /
// |                                               |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                      TYPE                     |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                     CLASS                     |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                      TTL                      |
// |                                               |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                   RDLENGTH                    |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
// /                     RDATA                     /
// /                                               /
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//
// See: https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.3
type RR struct {
	// Name is the domain name to which this resource record belongs.
	Name string

	// Type specifies the meaning of the data in the RDATA field.
	Type Type

	// Class specifies the class of the data in the RDATA field.
	Class Class

	// TTL specifies the time (in seconds) that the resource record may be cached.
	TTL uint32

	// RDLength specifies the length (in bytes) of the RDATA field.
	RDLength uint16

	// RData describes the resource itself, where the format of this information
	// varies depending on the TYPE and CLASS of the resource record.
	RData []byte

	// RDataUnpacked is a custom field that holds the unpacked RData.
	// Depending on the Type, RData may or may not hold a domain name. And when
	// RData holds a domain name, it can be compressed.
	RDataUnpacked string
}

// Unpack unpacks the DNS message resource record bytes (big-endian; network
// order). It returns either the unpacked byte count or an error.
func (r *RR) Unpack(msg []byte, off int) (int, error) {
	bytesRead := 0

	name, offn, n := unpackDomainName(msg, off)
	r.Name = name
	off = offn
	bytesRead += n

	// The remaining bytes contain the remaining sections; left-shift the first
	// byte to the "left most" position, and OR it with the remaining byte(s) to
	// "merge" it back into a single section.
	//
	// Type and Class are 2 bytes each.
	r.Type = Type(uint16(msg[off])<<8 | uint16(msg[off+1]))
	r.Class = Class(uint16(msg[off+2])<<8 | uint16(msg[off+3]))
	bytesRead += 4

	// TTL consists of 4 bytes.
	r.TTL = uint32(msg[off+4])<<24 |
		uint32(msg[off+5])<<16 |
		uint32(msg[off+6])<<8 |
		uint32(msg[off+7])
	bytesRead += 4

	// RDLength consists of 2 bytes.
	r.RDLength = uint16(msg[off+8])<<8 | uint16(msg[off+9])
	bytesRead += 2

	// RData consists of the remaining RDLength bytes.
	// TYPE + CLASS + TTL + RDLENGTH = 10 bytes.
	start := off + 10
	size := int(r.RDLength)
	end := start + size
	r.RData = msg[start:end]
	bytesRead += size

	// Depending on the RR Type, RData has to be unpacked differently.
	switch r.Type {
	// RDATA will contain a 32 bit IP address; needs no additional processing.
	//
	// https://datatracker.ietf.org/doc/html/rfc1035#section-3.4.1
	case TypeA:
		ip := append(net.IP{}, r.RData...)
		r.RDataUnpacked = ip.String()

	// TODO: TypeAAAA
	//
	// See: https://datatracker.ietf.org/doc/html/rfc3596

	// RDATA will contain a domain name which specifies the canonical or primary
	// name for the owner. The owner name is an alias.
	//
	// See: https://datatracker.ietf.org/doc/html/rfc1035#section-3.3.1
	case TypeCNAME:
		name, _, _ := unpackDomainName(msg, start)
		r.RDataUnpacked = name

	// RDATA will contain a domain name (NSDNAME) which specifies a host which
	// should be authoritative for the specified class and domain.
	//
	// See: https://datatracker.ietf.org/doc/html/rfc1035#section-3.3.11
	case TypeNS:
		name, _, _ := unpackDomainName(msg, start)
		r.RDataUnpacked = name

	// See: https://datatracker.ietf.org/doc/html/rfc1035#section-3.3.13
	case TypeSOA:
		// TODO

	// See: https://datatracker.ietf.org/doc/html/rfc1035#section-3.3.14
	case TypeTXT:
		// TODO
	}

	return bytesRead, nil
}

// String returns a "dig like" string representation of the resource.
func (r *RR) String() string {
	return fmt.Sprintf(
		"%s\t%d\t%s\t%s\t%s",
		r.Name,
		r.TTL,
		ClassToString[r.Class],
		TypeToString[r.Type],
		r.RDataUnpacked,
	)
}
