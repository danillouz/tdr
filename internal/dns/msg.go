package dns

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
