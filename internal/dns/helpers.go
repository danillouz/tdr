package dns

// queryByteMask creates a mask where the "right most" n bits in a byte are
// "turned on".
//
//   7   6   5   4   3   2   1   0
// +---+---+---+---+---+---+---+---+
// | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |	(1 << 0 ) - 1 = 0
// +---+---+---+---+---+---+---+---+
// | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1 |	(1 << 1 ) - 1 = 1
// +---+---+---+---+---+---+---+---+
// | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 1 |	(1 << 2 ) - 1 = 3
// +---+---+---+---+---+---+---+---+
// | 0 | 0 | 0 | 0 | 0 | 1 | 1 | 1 |	(1 << 3 ) - 1 = 7
// +---+---+---+---+---+---+---+---+
// | 0 | 0 | 0 | 0 | 1 | 1 | 1 | 1 |	(1 << 4 ) - 1 = 15
// +---+---+---+---+---+---+---+---+
// | 0 | 0 | 0 | 1 | 1 | 1 | 1 | 1 |	(1 << 5 ) - 1 = 31
// +---+---+---+---+---+---+---+---+
// | 0 | 0 | 1 | 1 | 1 | 1 | 1 | 1 |	(1 << 6 ) - 1 = 63
// +---+---+---+---+---+---+---+---+
// | 0 | 1 | 1 | 1 | 1 | 1 | 1 | 1 |	(1 << 7 ) - 1 = 127
// +---+---+---+---+---+---+---+---+
// | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 |	(1 << 8 ) - 1 = 255
// +---+---+---+---+---+---+---+---+
func queryByteMask(n int) byte {
	return (1 << n) - 1
}

// unpackDomainName unpacks a domain name 1 label at a time, and follows any
// pointer(s) when the domain name is compressed. It returns the unpacked
// domain name, the next offset, and the amount of bytes read.
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
// found; each label (after following the pointer) always start with a length
// byte (i.e. label size), followed by the "actual" label byte(s).
//
// This means that a domain name in a message can be either:
// - A sequence of labels ending in a zero byte.
// - A pointer (that points to a sequence of labels ending in a zero byte).
// - A sequence of labels ending with a pointer (that points to a sequence of
//   labels ending in a zero byte).
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
//
// See: https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.4
func unpackDomainName(msg []byte, off int) (string, int, int) {
	nameb := []byte{}

	// The number of pointers followed.
	ptrn := 0

	// The current offset of a label.
	offl := off

	for {
		// The current byte. Can be either:
		// - A pointer; in this case the second byte (i.e. `cb` + 1) points to the
		//   length byte.
		// - Not a pointer; in this case the current byte _is_ the length byte.
		cb := msg[offl]

		// Because a pointer starts with its 2 most significant bits set to 1,
		// right-shifting them to the "right most" position results in
		// 2^1 + 2^0 = 3.
		isPointer := (cb >> 6) == 3
		if isPointer {
			// To get the offset pointer value, "query" the 6 "right most" bits of the
			// first pointer byte, and "merge" it with the second pointer byte; a
			// pointer always consists of 2 bytes.
			p := uint16(cb&queryByteMask(6)) | uint16(msg[offl+1])
			offp := int(p)
			offl = offp
			ptrn++
			continue
		}

		size := int(cb)

		// The next byte always starts after the length byte.
		offl += 1

		if size == 0 {
			break
		}

		end := offl + size
		nameb = append(nameb, msg[offl:end]...)
		nameb = append(nameb, '.')
		offl = end
	}

	name := string(nameb)
	offn := offl
	bytesRead := offl - off

	if ptrn > 0 {
		// A pointer always consists of 2 bytes.
		psize := 2
		offn = off + psize
		bytesRead = psize
	}

	return name, offn, bytesRead
}
