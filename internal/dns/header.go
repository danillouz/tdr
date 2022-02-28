package dns

// OpCode represents a DNS operation code.
type OpCode byte

const (
	// OpCodeQuery is a standard query.
	OpCodeQuery OpCode = iota

	// OpCodeIQuery is an inverse query.
	OpCodeIQuery

	// OpCodeStatus is a server status request.
	OpCodeStatus
)

// RCode represents a DNS response code.
type RCode byte

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

// Header represents the DNS message header.
// It has the following format:
//
//                                 1  1  1  1  1  1
//   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
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
