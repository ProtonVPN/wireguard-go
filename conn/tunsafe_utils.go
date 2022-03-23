/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2021 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"bytes"
	"encoding/binary"
	"errors"
)

var wgDataPrefix = []byte{4, 0, 0, 0}
var wgDataHeaderSize = 16
var wgDataPrefixSize = 8 // Wireguard data header without counter

var tunSafeHeaderSize = 2
var tunSafeNormalType = uint8(0b00)
var tunSafeDataType = uint8(0b10)

type TunSafeData struct {
	wgSendPrefix []byte
	wgSendCount  uint64
	wgRecvPrefix []byte
	wgRecvCount  uint64
}

var topLevelDomains = []string{".com", ".org", ".net"}

func NewTunSafeData() *TunSafeData {
	return &TunSafeData{
		wgRecvPrefix: make([]byte, 8),
		wgSendPrefix: make([]byte, 8),
	}
}

// Returns (type, size)
func parseTunSafeHeader(header []byte) (byte, int) {
	tunSafeType := header[0] >> 6
	size := (int(header[0])&0b00111111)<<8 | int(header[1])
	return tunSafeType, size
}

func (tunSafe *TunSafeData) writeWgHeader(wgPacket []byte) {
	buffer := new(bytes.Buffer)
	buffer.Grow(len(tunSafe.wgRecvPrefix) + binary.Size(tunSafe.wgRecvCount))
	buffer.Write(tunSafe.wgRecvPrefix)
	_ = binary.Write(buffer, binary.LittleEndian, tunSafe.wgRecvCount)
	copy(wgPacket, buffer.Bytes())
}

func (tunSafe *TunSafeData) prepareWgPacket(tunSafeType byte, payloadSize int) ([]byte, int, error) {
	var wgPacket []byte
	offset := 0
	switch tunSafeType {
	case tunSafeNormalType:
		wgPacket = make([]byte, payloadSize)
	case tunSafeDataType:
		offset = wgDataHeaderSize
		wgPacket = make([]byte, payloadSize+offset)
		tunSafe.writeWgHeader(wgPacket)
	default:
		return nil, 0, errors.New("StdNetBindTcp: unknown TunSafe type")
	}
	return wgPacket, offset, nil
}

func (tunSafe *TunSafeData) onRecvPacket(tunSafeType byte, wgPacket []byte) {
	if tunSafeType == tunSafeNormalType {
		isWgDataPacket := bytes.HasPrefix(wgPacket, wgDataPrefix)
		if isWgDataPacket {
			copy(tunSafe.wgRecvPrefix, wgPacket[:wgDataPrefixSize])
			countBuffer := bytes.NewBuffer(wgPacket[wgDataPrefixSize:wgDataHeaderSize])
			_ = binary.Read(countBuffer, binary.LittleEndian, &tunSafe.wgRecvCount)
		}
	}
	tunSafe.wgRecvCount++
}

func (tunSafe *TunSafeData) wgToTunSafe(wgPacket []byte) []byte {
	wgLen := len(wgPacket)
	if wgLen < wgDataHeaderSize {
		return wgToTunSafeNormal(wgPacket)
	}
	wgPrefix := wgPacket[:wgDataPrefixSize]
	var wgCount uint64
	_ = binary.Read(bytes.NewReader(wgPacket[wgDataPrefixSize:wgDataHeaderSize]), binary.LittleEndian, &wgCount)
	prefixMatch := bytes.Equal(wgPrefix, tunSafe.wgSendPrefix)
	if prefixMatch && wgCount == tunSafe.wgSendCount+1 {
		tunSafe.wgSendCount += 1
		return wgToTunSafeData(wgPacket)
	} else {
		isWgDataPacket := bytes.HasPrefix(wgPacket, wgDataPrefix)
		if isWgDataPacket {
			tunSafe.wgSendPrefix = wgPrefix
			tunSafe.wgSendCount = wgCount
		}
		return wgToTunSafeNormal(wgPacket)
	}
}

func wgToTunSafeNormal(wgPacket []byte) []byte {
	payloadSize := len(wgPacket)
	result := make([]byte, payloadSize+tunSafeHeaderSize)

	// Tunsafe normal header
	result[0] = uint8(payloadSize >> 8)
	result[1] = uint8(payloadSize & 0xff)

	// Full packet
	copy(result[tunSafeHeaderSize:], wgPacket)

	return result
}

func wgToTunSafeData(wgPacket []byte) []byte {
	payloadSize := len(wgPacket) - wgDataHeaderSize
	result := make([]byte, payloadSize+tunSafeHeaderSize)

	// TunSafe data header
	result[0] = uint8(0b10<<6 | payloadSize>>8)
	result[1] = uint8(payloadSize & 0xff)

	// Packet without header
	copy(result[tunSafeHeaderSize:], wgPacket[wgDataHeaderSize:])

	return result
}
