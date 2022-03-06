package dns

// unpackDomainNameLabel unpacks a domain name 1 label at a time. It returns
// the label size in bytes, the label, and the next offset (to read the next
// label).
//
// Because domain names can be compressed, we first check if a label is a
// pointer.
//
// When compressed, the label(s) of the domain name are replaced with a
// pointer to a prior occurance. The pointer consists of 2 bytes and has the
// following format:
//
//  15 14 13 12 11 10  9  8  7  6  5  4  3  2  1  0
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// | 1  1|                OFFSET                   |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//
// The first 2 bits are always set to 1. And OFFSET specifies the offset from
// the _start_ of the message (i.e. `Msg.Header.ID`) where the label can be
// found; each label will start with a length byte, followed by the actual
// label byte(s).
//
// This means that a domain name in a message can be either:
// - A sequence of labels ending in a zero byte.
// - A pointer.
// - A sequence of labels ending with a pointer.
//
// For example, the domain names `dan.co` and `hey.dan.co` can be
// compressed like:
//
//     15 14 13 12 11 10  9  8  7  6  5  4  3  2  1  0
// ..
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// 20 |    3 (length byte)    |           d           |
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// 22 |           a           |           n           |
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// 24 |    2 (length byte)    |           c           |
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// 26 |           o           |     0 (zero byte)     |
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// ..
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// 40 |    3 (length byte)    |           h           |
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// 42 |           e           |           y           |
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// 44 | 1  1|        20 (offset pointer)              |
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// ..
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// 64 | 1  1|        24 (offset pointer)              |
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// ..
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// 92 |    0 (root domain     |                       |
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//
// See: https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.4
func unpackNameLabel(msg []byte, off int) (lsize int, label string, offn int) {
	// Because a pointer starts with 2 bits set to 1, right-shifting them to the
	// "right most" position results in 2^1 + 2^0 = 3.
	isPointer := (msg[off] >> 6) == 3
	offp := 0

	if isPointer {
		// To get the offset pointer value, query the 6 "right most" bits of the
		// first pointer byte, and "merge" it with the second pointer byte; a
		// pointer always consists of 2 bytes.
		p := uint16(msg[off]&queryByteMask(6)) | uint16(msg[off]+1)
		offp = int(p)

		// Follow the offset pointer to get the length byte of the label.
		lsize = int(msg[offp])
	} else {
		// When the label is not compressed, the first byte in the sequence will
		// always be the length byte.
		lsize = int(msg[off])
	}

	start := 0

	// The label byte(s) start after the length byte.
	if isPointer {
		start = offp + 1
	} else {
		start = off + 1
	}

	end := start + lsize

	label = string(msg[start:end])

	if isPointer {
		// A pointer always consists of 2 bytes.
		offn = 2
	} else {
		offn = end
	}

	return
}
