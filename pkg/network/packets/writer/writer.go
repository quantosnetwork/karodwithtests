package writer

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"karodwithtests/pkg/network/packets/format"
)

func Write(cmd uint8, chainType uint16, dataType uint32, Payload []byte, Encrypted uint8, Compressed uint8) []byte {
	f := format.GetNewPacketFormatter(cmd, chainType, dataType, Payload, Encrypted, Compressed)
	buf := f.Buf
	buf[format.IdxCmdPosFrom] = cmd
	bct := WriteUint16(chainType)
	copy(buf[format.IdxChainTypeFrom:format.IdxChainTypeTo], bct)
	bcd := WriteUint32(dataType)
	copy(buf[format.IdxDataTypeFrom:format.IdxDataTypeTo], bcd)
	buf[format.IdxOptionsFrom] = Encrypted
	buf[format.IdxOptionsFrom+4] = Compressed
	payloadSize := len(Payload)
	copy(buf[format.IdxSizeFrom:format.IdxSizeTo], WriteUint32(uint32(payloadSize)))
	bufLen := len(buf) - 1
	copy(buf[bufLen:payloadSize], Payload)
	chksum := crc32.ChecksumIEEE(Payload)
	copy(buf[len(buf)-1:], WriteUint32(chksum))
	return buf
}

func WriteUint16(i uint16) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, i)
	return buf.Bytes()
}

func WriteUint32(i uint32) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, i)
	return buf.Bytes()
}
