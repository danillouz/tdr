package dns

import "testing"

func TestHeaderPackUnpack(t *testing.T) {
	msg := Header{
		ID:      1,
		QR:      1,
		OpCode:  OpCodeQuery,
		AA:      1,
		TC:      1,
		RD:      1,
		RA:      0,
		Z:       0,
		RCode:   RCodeNoError,
		QDCount: 1,
		ANCount: 2,
		NSCount: 1,
		ARCount: 4,
	}

	b, err := msg.Pack()
	if err != nil {
		t.Fatal(err)
	}

	h := new(Header)
	lenb, err := h.Unpack(b)
	if err != nil {
		t.Fatal(err)
	}
	if lenb != len(b) {
		t.Errorf("unpacked bytes length error: got %v - want %v", lenb, len(b))
	}

	if h.ID != msg.ID {
		t.Errorf("unpacked header ID error: got %v - want %v", h.ID, msg.ID)
	}
	if h.QR != msg.QR {
		t.Errorf("unpacked header QR error: got %v - want %v", h.QR, msg.QR)
	}
	if h.OpCode != msg.OpCode {
		t.Errorf(
			"unpacked header OpCode error: got %v - want %v", h.OpCode, msg.OpCode,
		)
	}
	if h.AA != msg.AA {
		t.Errorf("unpacked header AA error: got %v - want %v", h.AA, msg.AA)
	}
	if h.TC != msg.TC {
		t.Errorf("unpacked header TC error: got %v - want %v", h.TC, msg.TC)
	}
	if h.RD != msg.RD {
		t.Errorf("unpacked header RD error: got %v - want %v", h.RD, msg.RD)
	}
	if h.RA != msg.RA {
		t.Errorf("unpacked header RA error: got %v - want %v", h.RA, msg.RA)
	}
	if h.Z != msg.Z {
		t.Errorf("unpacked header Z error: got %v - want %v", h.Z, msg.Z)
	}
	if h.RCode != msg.RCode {
		t.Errorf(
			"unpacked header RCode error: got %v - want %v", h.RCode, msg.RCode,
		)
	}
	if h.QDCount != msg.QDCount {
		t.Errorf(
			"unpacked header QDCount error: got %v - want %v", h.QDCount, msg.QDCount,
		)
	}
	if h.ANCount != msg.ANCount {
		t.Errorf(
			"unpacked header ANCount error: got %v - want %v", h.ANCount, msg.ANCount,
		)
	}
	if h.NSCount != msg.NSCount {
		t.Errorf(
			"unpacked header NSCount error: got %v - want %v", h.NSCount, msg.NSCount,
		)
	}
	if h.ARCount != msg.ARCount {
		t.Errorf(
			"unpacked header ARCount error: got %v - want %v", h.ARCount, msg.ARCount,
		)
	}
}
