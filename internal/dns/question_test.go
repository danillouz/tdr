package dns

import "testing"

func TestQuestionPackUnpack(t *testing.T) {
	msg := Question{
		QName:  "danillouz.dev",
		QType:  TypeA,
		QClass: ClassIN,
	}

	b, err := msg.Pack()
	if err != nil {
		t.Fatal(err)
	}

	q := new(Question)
	lenb, err := q.Unpack(b)
	if err != nil {
		t.Fatal(err)
	}
	if lenb != len(b) {
		t.Errorf("unpacked bytes length error: got %v - want %v", lenb, len(b))
	}

	if q.QName != msg.QName {
		t.Errorf(
			"unpacked question QName error: got %v - want %v", q.QName, msg.QName,
		)
	}
	if q.QType != msg.QType {
		t.Errorf(
			"unpacked question QType error: got %v - want %v", q.QType, msg.QType,
		)
	}
	if q.QClass != msg.QClass {
		t.Errorf(
			"unpacked question QClass error: got %v - want %v", q.QClass, msg.QClass,
		)
	}
}
