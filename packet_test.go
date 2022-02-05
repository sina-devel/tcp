package tcp

import (
	"testing"
)

func TestPacket_SourcePort(t *testing.T) {
	p := Packet{
		0x30, 0x39, 0xd4, 0x31, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00, 0x70, 0x02,
		0x00, 0x00, 0x82, 0x9c, 0x00, 0x00, 0x02, 0x04, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x54, 0x65,
		0x73, 0x74,
	}

	var expected uint16 = 12345

	if got := p.SourcePort(); got != expected {
		t.Errorf("Packet.SourcePort(): got %d, expected %d", got, expected)
	}
}

func TestPacket_DestinationPort(t *testing.T) {
	p := Packet{
		0x30, 0x39, 0xd4, 0x31, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00, 0x70, 0x02,
		0x00, 0x00, 0x82, 0x9c, 0x00, 0x00, 0x02, 0x04, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x54, 0x65,
		0x73, 0x74,
	}

	var expected uint16 = 54321

	if got := p.DestinationPort(); got != expected {
		t.Errorf("Packet.DestinationPort(): got %d, expected %d", got, expected)
	}
}

func TestPacket_SequenceNumber(t *testing.T) {
	p := Packet{
		0x30, 0x39, 0xd4, 0x31, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00, 0x70, 0x02,
		0x00, 0x00, 0x82, 0x9c, 0x00, 0x00, 0x02, 0x04, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x54, 0x65,
		0x73, 0x74,
	}

	var expected uint32 = 3735928559

	if got := p.SequenceNumber(); got != expected {
		t.Errorf("Packet.SequenceNumber(): got %d, expected %d", got, expected)
	}
}

func TestPacket_AckNumber(t *testing.T) {
	p := Packet{
		0x30, 0x39, 0xd4, 0x31, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00, 0x70, 0x02,
		0x00, 0x00, 0x82, 0x9c, 0x00, 0x00, 0x02, 0x04, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x54, 0x65,
		0x73, 0x74,
	}

	var expected uint32 = 0

	if got := p.AckNumber(); got != expected {
		t.Errorf("Packet.AckNumber(): got %d, expected %d", got, expected)
	}
}

func TestPacket_DataOffset(t *testing.T) {
	p := Packet{
		0x30, 0x39, 0xd4, 0x31, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00, 0x70, 0x02,
		0x00, 0x00, 0x82, 0x9c, 0x00, 0x00, 0x02, 0x04, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x54, 0x65,
		0x73, 0x74,
	}

	var expected uint8 = 28

	if got := p.DataOffset(); got != expected {
		t.Errorf("Packet.DataOffset(): got %d, expected %d", got, expected)
	}
}

func TestPacket_Window(t *testing.T) {
	p := Packet{
		0x30, 0x39, 0xd4, 0x31, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00, 0x70, 0x02,
		0x00, 0x00, 0x82, 0x9c, 0x00, 0x00, 0x02, 0x04, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x54, 0x65,
		0x73, 0x74,
	}

	var expected uint16 = 0

	if got := p.Window(); got != expected {
		t.Errorf("Packet.Window(): got %d, expected %d", got, expected)
	}
}

func TestPacket_Checksum(t *testing.T) {
	p := Packet{
		0x30, 0x39, 0xd4, 0x31, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00, 0x70, 0x02,
		0x00, 0x00, 0x82, 0x9c, 0x00, 0x00, 0x02, 0x04, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x54, 0x65,
		0x73, 0x74,
	}

	var expected uint16 = 33436

	if got := p.Checksum(); got != expected {
		t.Errorf("Packet.Checksum(): got %d, expected %d", got, expected)
	}
}
