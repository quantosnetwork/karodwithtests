package format

import "hash/crc32"

const MaxBytes = 4096
const EOLSymbol = '\n'
const PrefixIdent = 'Q'

//Cmd is 4 bytes
var Cmd = map[string]uint8{
	"HANDSHAKE":   'h',
	"KYBERKX":     'k',
	"VALIDATE":    'v',
	"SIGN":        's',
	"REQDATA":     'r',
	"SERVICEINFO": 'i',
	"SENDTX":      't',
	"RECVTX":      'w',
	"PING":        'p',
}

const IdxCmdPosFrom = 0
const IdxCmdPosTo = 4
const IdxChainTypeFrom = 4
const IdxChainTypeTo = 12
const IdxDataTypeFrom = 12
const IdxDataTypeTo = 28
const IdxOptionsFrom = 28
const IdxOptionsTo = 52
const IdxSizeFrom = 52
const IdxSizeTo = 68
const PayloadFrom = 68

// ChainType is 8 bytes
var ChainType = map[string]uint16{
	"LIVE":     0x0A00,
	"TESTNET":  0x0BFF,
	"INTERNAL": 0x0DDD,
}

// DataType is 16 bytes
var DataType = map[string]uint32{
	"NULL":          0x00000000,
	"HANDSHAKERESP": 0x00000001,
	"RESPONSE":      0x00A00001,
	"ERROR":         0x00A00004,
	"AUTHDATA":      0x00A00005,
	"QUANTOSPFX":    0x00A00000,
	"STREAM":        0x00B0C272,
	"BISTREAM":      0x00B0C273,
	"KEYS":          0x0001A270,
	"ADDR":          0x009429BE,
	"GRPC":          0x06256580,
	"GENESIS":       0x06BDD106,
	"BLOCKHEAD":     0x00ADEBD8,
	"BLOCK":         0x00ADEBDC,
	"PEERS":         0x00AD0000,
	"PEERREQ":       0x00AD1000,
	"PEERINFO":      0x00AD2000,
}

type PacketOptions struct {
	Encrypted  uint8
	Compressed uint8
}

type PacketFormatter struct {
	Buf       []byte
	EolSep    byte
	Prefix    byte
	Command   uint8
	ChainType uint16
	DataType  uint32
	Payload   []byte
	Options   *PacketOptions
	Size      int32
	Checksum  uint32
}

func (f *PacketFormatter) New(cmd uint8, chainType uint16, DataType uint32, Payload []byte, Encrypted uint8, Compressed uint8) {
	f.Buf = make([]byte, 0, MaxBytes)
	f.EolSep = EOLSymbol
	f.Prefix = PrefixIdent
	f.Command = cmd
	f.ChainType = chainType
	f.DataType = DataType
	f.Payload = Payload
	f.Size = int32(len(f.Payload))
	f.Checksum = crc32.ChecksumIEEE(f.Payload)
	f.Options = &PacketOptions{Encrypted: Encrypted, Compressed: Compressed}
}

func GetNewPacketFormatter(cmd uint8, chainType uint16, DataType uint32, Payload []byte, Encrypted uint8, Compressed uint8) *PacketFormatter {
	f := &PacketFormatter{}
	f.New(cmd, chainType, DataType, Payload, Encrypted, Compressed)
	return f
}
