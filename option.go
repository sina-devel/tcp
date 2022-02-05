package tcp

type OptionKind uint8

const (
	OptionKindEndList OptionKind = iota
	OptionKindNop
	OptionKindMSS                             // len = 4
	OptionKindWindowScale                     // len = 3
	OptionKindSACKPermitted                   // len = 2
	OptionKindSACK                            // len = n
	OptionKindEcho                            // len = 6, obsolete
	OptionKindEchoReply                       // len = 6, obsolete
	OptionKindTimestamps                      // len = 10
	OptionKindPartialOrderConnectionPermitted // len = 2, obsolete
	OptionKindPartialOrderServiceProfile      // len = 3, obsolete
	OptionKindCC                              // obsolete
	OptionKindCCNew                           // obsolete
	OptionKindCCEcho                          // obsolete
	OptionKindAltChecksum                     // len = 3, obsolete
	OptionKindAltChecksumData                 // len = n, obsolete
)

func (k OptionKind) String() string {
	switch k {
	case OptionKindEndList:
		return "EndList"
	case OptionKindNop:
		return "NOP"
	case OptionKindMSS:
		return "MSS"
	case OptionKindWindowScale:
		return "WindowScale"
	case OptionKindSACKPermitted:
		return "SACKPermitted"
	case OptionKindSACK:
		return "SACK"
	case OptionKindEcho:
		return "Echo"
	case OptionKindEchoReply:
		return "EchoReply"
	case OptionKindTimestamps:
		return "Timestamps"
	case OptionKindPartialOrderConnectionPermitted:
		return "PartialOrderConnectionPermitted"
	case OptionKindPartialOrderServiceProfile:
		return "PartialOrderServiceProfile"
	case OptionKindCC:
		return "CC"
	case OptionKindCCNew:
		return "CCNew"
	case OptionKindCCEcho:
		return "CCEcho"
	case OptionKindAltChecksum:
		return "AltChecksum"
	case OptionKindAltChecksumData:
		return "AltChecksumData"
	default:
		return "Unknown"
	}
}

type Option struct {
	Kind   OptionKind
	Length uint8
	Data   []byte
}

type Options []byte

func (o Options) HasNext() bool {
	return len(o) > 0
}

func (o *Options) Next() Option {
	opt := Option{Kind: OptionKind((*o)[0])}

	switch opt.Kind {
	case OptionKindEndList, OptionKindNop:
		opt.Length = 1
		*o = (*o)[opt.Length:]
	default:
		opt.Length = (*o)[1]
		opt.Data = (*o)[2:opt.Length]
		*o = (*o)[opt.Length:]

	}

	return opt
}
