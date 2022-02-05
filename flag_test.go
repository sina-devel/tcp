package tcp

import (
	"testing"
)

func TestFlag(t *testing.T) {
	p := Packet{
		0x30, 0x39, 0xd4, 0x31, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00, 0x70, 0x02,
		0x00, 0x00, 0x82, 0x9c, 0x00, 0x00, 0x02, 0x04, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x54, 0x65,
		0x73, 0x74,
	}

	expected := Flags{
		SYN: true,
	}

	got := Flags{
		Reserved1: p.FlagReserved1(),
		Reserved2: p.FlagReserved2(),
		Reserved3: p.FlagReserved3(),
		NS:        p.FlagNS(),
		CWR:       p.FlagCWR(),
		ECE:       p.FlagECE(),
		URG:       p.FlagURG(),
		ACK:       p.FlagACK(),
		PSH:       p.FlagPSH(),
		RST:       p.FlagRST(),
		SYN:       p.FlagSYN(),
		FIN:       p.FlagFIN(),
	}

	if got != expected {
		t.Errorf("Flags: got %+v, expected %+v", got, expected)
	}
}

func TestSetFlag(t *testing.T) {
	p := Packet{
		0x30, 0x39, 0xd4, 0x31, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00, 0x70, 0x00,
		0x00, 0x00, 0x82, 0x9c, 0x00, 0x00, 0x02, 0x04, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x54, 0x65,
		0x73, 0x74,
	}

	p.SetFlagFIN()

	expected := Flags{
		FIN: true,
	}

	got := Flags{
		Reserved1: p.FlagReserved1(),
		Reserved2: p.FlagReserved2(),
		Reserved3: p.FlagReserved3(),
		NS:        p.FlagNS(),
		CWR:       p.FlagCWR(),
		ECE:       p.FlagECE(),
		URG:       p.FlagURG(),
		ACK:       p.FlagACK(),
		PSH:       p.FlagPSH(),
		RST:       p.FlagRST(),
		SYN:       p.FlagSYN(),
		FIN:       p.FlagFIN(),
	}

	if got != expected {
		t.Errorf("Flags: got %+v, expected %+v", got, expected)
	}
}

func TestUnsetFlag(t *testing.T) {
	p := Packet{
		0x30, 0x39, 0xd4, 0x31, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00, 0x70, 0x02,
		0x00, 0x00, 0x82, 0x9c, 0x00, 0x00, 0x02, 0x04, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x54, 0x65,
		0x73, 0x74,
	}

	p.UnsetFlagFIN()

	expected := Flags{
		SYN: true,
	}

	got := Flags{
		Reserved1: p.FlagReserved1(),
		Reserved2: p.FlagReserved2(),
		Reserved3: p.FlagReserved3(),
		NS:        p.FlagNS(),
		CWR:       p.FlagCWR(),
		ECE:       p.FlagECE(),
		URG:       p.FlagURG(),
		ACK:       p.FlagACK(),
		PSH:       p.FlagPSH(),
		RST:       p.FlagRST(),
		SYN:       p.FlagSYN(),
		FIN:       p.FlagFIN(),
	}

	if got != expected {
		t.Errorf("Flags: got %+v, expected %+v", got, expected)
	}
}
