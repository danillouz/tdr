package dns

// Type represents a DNS resource record type.
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

// Class represents a DNS resource record class.
//
// See: https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.4
type Class uint16

const (
	ClassUnknown Class = iota

	// ClassIN stands for the internet.
	ClassIN
)

// RR represents a resource record.
// The message answer, authority, and additional sections all share the same
// format: a variable number of resource records, where the number of records
// is specified in the corresponding count field in the message header.
// Each resource record has the following format:
//
//                                 1  1  1  1  1  1
//   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
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
}
