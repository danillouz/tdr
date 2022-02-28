package dns

// QType fields appear in the question section of a DNS query.
// QTypes are a superset of Types, so every Type is a valid QType.
//
// See: https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.3
type QType = Type

// QClass fields appear in the question section of a DNS query.
// QClass values are a superset of Class values, so every Class is a valid
// QClass.
//
// See: https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.5
type QClass = Class

// Question represents the question (i.e. query) to a name server.
// It has the following format:
//
//                                 1  1  1  1  1  1
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
	// QName is a domain name represented as a sequence of labels. Each label
	// consists of a length byte followed by that number of bytes. The domain
	// name terminates with the zero length byte for the null label of the root.
	// Note that this field may be an odd number of bytes; no padding is used.
	QName string

	// QType is a two byte code which specifies the type of the query.
	QType QType

	// QClass is a two byte code that specifies the class of the query.
	QClass QClass
}
