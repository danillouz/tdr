package dns

import "testing"

func TestMsgPackUnpack(t *testing.T) {
	msg := Msg{
		Header: Header{
			ID:      123,
			QR:      0,
			OpCode:  OpCodeQuery,
			RD:      1,
			QDCount: 1,
		},
		Question: Question{
			QName:  "danillouz.dev",
			QType:  TypeA,
			QClass: ClassIN,
		},
	}

	b, err := msg.Pack()
	if err != nil {
		t.Fatal(err)
	}

	m := new(Msg)
	lenb, err := m.Unpack(b)
	if err != nil {
		t.Fatal(err)
	}
	if lenb != len(b) {
		t.Errorf("unpacked bytes length error: got %v - want %v", lenb, len(b))
	}

	if m.Header.ID != msg.ID {
		t.Errorf(
			"unpacked message header ID error: got %v - want %v", m.Header.ID, msg.ID,
		)
	}

	if m.Question.QName != msg.Question.QName+"." {
		t.Errorf(
			"unpacked message question QName error: got %v - want %v",
			m.Question.QName, msg.Question.QName+".",
		)
	}
	if m.Question.QType != msg.Question.QType {
		t.Errorf(
			"unpacked message question QType error: got %v - want %v",
			m.Question.QType, msg.Question.QType,
		)
	}
	if m.Question.QClass != msg.Question.QClass {
		t.Errorf(
			"unpacked message question QClass error: got %v - want %v",
			m.Question.QClass, msg.Question.QClass,
		)
	}
}
