package tcp

import (
	"github.com/GeniusesGroup/libgo/binary"
)

type Packet []byte

func (p Packet) SourcePort() uint16 {
	return binary.BigEndian.Uint16(p[:2])
}

func (p Packet) DestinationPort() uint16 {
	return binary.BigEndian.Uint16(p[2:4])
}

func (p Packet) SequenceNumber() uint32 {
	return binary.BigEndian.Uint32(p[4:8])
}

func (p Packet) AckNumber() uint32 {
	return binary.BigEndian.Uint32(p[8:12])
}

func (p Packet) DataOffset() uint8 {
	return (p[12] >> 4) * 4
}

func (p Packet) Window() uint16 {
	return binary.BigEndian.Uint16(p[14:16])
}

func (p Packet) Checksum() uint16 {
	return binary.BigEndian.Uint16(p[16:18])
}

func (p Packet) UrgentPointer() uint16 {
	return binary.BigEndian.Uint16(p[18:20])
}

func (p Packet) Options() Options {
	return Options(p[20:p.DataOffset()])
}

func (p Packet) SetSourcePort(port uint16) {
	binary.BigEndian.PutUint16(p[:2], port)
}

func (p Packet) SetDestinationPort(port uint16) {
	binary.BigEndian.PutUint16(p[2:4], port)
}

func (p Packet) SetSequenceNumber(v uint32) {
	binary.BigEndian.PutUint32(p[4:8], v)
}

func (p Packet) SetAckNumber(v uint32) {
	binary.BigEndian.PutUint32(p[8:12], v)
}

func (p Packet) SetDataOffset(v uint8) {
	p[12] = byte((v/4)<<4) | byte(p[12]>>4)
}

func (p Packet) SetWindow(v uint16) {
	binary.BigEndian.PutUint16(p[14:16], v)
}

func (p Packet) SetChecksum(v uint16) {
	binary.BigEndian.PutUint16(p[16:18], v)
}

func (p Packet) SetUrgentPointer(v uint16) {
	binary.BigEndian.PutUint16(p[18:20], v)
}

func (p Packet) FlagReserved1() bool {
	return p[12]&FlagReserved1 == FlagReserved1
}

func (p Packet) FlagReserved2() bool {
	return p[12]&FlagReserved2 == FlagReserved2
}

func (p Packet) FlagReserved3() bool {
	return p[12]&FlagReserved3 == FlagReserved3
}

func (p Packet) FlagNS() bool {
	return p[12]&FlagNS == FlagNS
}

func (p Packet) FlagCWR() bool {
	return p[13]&FlagCWR == FlagCWR
}

func (p Packet) FlagECE() bool {
	return p[13]&FlagECE == FlagECE
}

func (p Packet) FlagURG() bool {
	return p[13]&FlagURG == FlagURG
}

func (p Packet) FlagACK() bool {
	return p[13]&FlagACK == FlagACK
}

func (p Packet) FlagPSH() bool {
	return p[13]&FlagPSH == FlagPSH
}

func (p Packet) FlagRST() bool {
	return p[13]&FlagRST == FlagRST
}

func (p Packet) FlagSYN() bool {
	return p[13]&FlagSYN == FlagSYN
}

func (p Packet) FlagFIN() bool {
	return p[13]&FlagFIN == FlagFIN
}

func (p Packet) SetFlagReserved1() {
	p[12] |= FlagReserved1
}

func (p Packet) SetFlagReserved2() {
	p[12] |= FlagReserved2
}

func (p Packet) SetFlagReserved3() {
	p[12] |= FlagReserved3
}

func (p Packet) SetFlagNS() {
	p[12] |= FlagNS
}

func (p Packet) SetFlagCWR() {
	p[13] |= FlagCWR
}

func (p Packet) SetFlagECE() {
	p[13] |= FlagECE
}

func (p Packet) SetFlagURG() {
	p[13] |= FlagURG
}

func (p Packet) SetFlagACK() {
	p[13] |= FlagACK
}

func (p Packet) SetFlagPSH() {
	p[13] |= FlagPSH
}

func (p Packet) SetFlagRST() {
	p[13] |= FlagRST
}

func (p Packet) SetFlagSYN() {
	p[13] |= FlagSYN
}

func (p Packet) SetFlagFIN() {
	p[13] |= FlagFIN
}

func (p Packet) UnsetFlagReserved1() {
	if p.FlagReserved1() {
		p[12] ^= FlagReserved1
	}
}

func (p Packet) UnsetFlagReserved2() {
	if p.FlagReserved2() {
		p[12] ^= FlagReserved2
	}
}

func (p Packet) UnsetFlagReserved3() {
	if p.FlagReserved3() {
		p[12] ^= FlagReserved3
	}
}

func (p Packet) UnsetFlagNS() {
	if p.FlagNS() {
		p[12] ^= FlagNS
	}
}

func (p Packet) UnsetFlagCWR() {
	if p.FlagCWR() {
		p[13] ^= FlagCWR
	}
}

func (p Packet) UnsetFlagECE() {
	if p.FlagECE() {
		p[13] ^= FlagECE
	}
}

func (p Packet) UnsetFlagURG() {
	if p.FlagURG() {
		p[13] ^= FlagURG
	}
}

func (p Packet) UnsetFlagACK() {
	if p.FlagACK() {
		p[13] ^= FlagACK
	}
}

func (p Packet) UnsetFlagPSH() {
	if p.FlagPSH() {
		p[13] ^= FlagPSH
	}
}

func (p Packet) UnsetFlagRST() {
	if p.FlagRST() {
		p[13] ^= FlagRST
	}
}

func (p Packet) UnsetFlagSYN() {
	if p.FlagSYN() {
		p[13] ^= FlagSYN
	}
}

func (p Packet) UnsetFlagFIN() {
	if p.FlagFIN() {
		p[13] ^= FlagFIN
	}
}
