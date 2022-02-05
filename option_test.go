package tcp

import (
	"reflect"
	"testing"
)

func TestOptions_Next(t *testing.T) {
	p := Packet{
		0x30, 0x39, 0xd4, 0x31, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00, 0x70, 0x02,
		0x00, 0x00, 0x82, 0x9c, 0x00, 0x00, 0x02, 0x04, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x54, 0x65,
		0x73, 0x74,
	}

	expecteds := []Option{
		{
			Kind:   OptionKindMSS,
			Length: 4,
			Data:   []byte{32, 0},
		},
		{
			Kind:   OptionKindEndList,
			Length: 1,
			Data:   nil,
		},
		{
			Kind:   OptionKindEndList,
			Length: 1,
			Data:   nil,
		},
		{
			Kind:   OptionKindEndList,
			Length: 1,
			Data:   nil,
		},
		{
			Kind:   OptionKindEndList,
			Length: 1,
			Data:   nil,
		},
	}

	o := p.Options()
	for i := 0; i < 4; i++ {
		expected := expecteds[i]
		if got := o.Next(); !reflect.DeepEqual(got, expected) {
			t.Errorf("Options.Next(): got %+v, expected %+v", got, expected)
		}
	}
}

func TestOptions_HasNext(t *testing.T) {
	p := Packet{
		0x30, 0x39, 0xd4, 0x31, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00, 0x70, 0x02,
		0x00, 0x00, 0x82, 0x9c, 0x00, 0x00, 0x02, 0x04, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x54, 0x65,
		0x73, 0x74,
	}

	expected := 5

	o := p.Options()

	got := 0
	for o.HasNext() {
		o.Next()
		got++
	}

	if got != expected {
		t.Errorf("Options.HasNext(): got %d options, expected %d options", got, expected)
	}
}
