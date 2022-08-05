/*
 * Copyright (c) 2022. Proton AG
 *
 * This file is part of ProtonVPN.
 *
 * ProtonVPN is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * ProtonVPN is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with ProtonVPN.  If not, see <https://www.gnu.org/licenses/>.
 */

package conn

import (
	"bytes"
	"errors"
	"github.com/refraction-networking/utls"
	"io"
	"net"
	"sync"
)

type StdNetBindTcp struct {
	mu sync.Mutex

	useTls        bool
	tcp           *net.TCPConn
	tls           *tls.UConn
	tlsError      error
	endpoint      *StdNetEndpoint
	currentPacket *bytes.Reader
	log           *Logger

	tunsafe *TunSafeData
}

//goland:noinspection GoUnusedExportedFunction
func CreateStdNetBind(socketType string, log *Logger) Bind {
	if socketType == "udp" {
		return NewStdNetBind()
	} else {
		return &StdNetBindTcp{tunsafe: NewTunSafeData(), useTls: socketType == "tls", log: log}
	}
}

func (bind *StdNetBindTcp) ParseEndpoint(s string) (Endpoint, error) {
	addr, err := parseEndpoint(s)
	endpoint := (*StdNetEndpoint)(addr)
	if err == nil {
		bind.endpoint = endpoint
	}
	return endpoint, err
}

func dialTcp(network string, IP net.IP, port int, listenPort int) (*net.TCPConn, int, error) {
	conn, err := net.DialTCP(network, &net.TCPAddr{Port: listenPort}, &net.TCPAddr{IP: IP, Port: port})
	if err != nil {
		return nil, 0, err
	}

	// Retrieve port.
	laddr := conn.LocalAddr()
	taddr, err := net.ResolveTCPAddr(
		laddr.Network(),
		laddr.String(),
	)
	if err != nil {
		_ = conn.Close()
		return nil, 0, err
	}
	return conn, taddr.Port, nil
}

func (bind *StdNetBindTcp) upgradeToTls() {
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         randomServerName(),
	}

	conn := tls.UClient(bind.tcp, tlsConf, tls.HelloChrome_Auto)
	err := conn.Handshake()
	if err != nil {
		bind.tlsError = err
	}
	bind.tls = conn
}

func (bind *StdNetBindTcp) Open(uport uint16) ([]ReceiveFunc, uint16, error) {
	bind.mu.Lock()
	defer bind.mu.Unlock()

	var err error

	if bind.tcp != nil {
		return nil, 0, ErrBindAlreadyOpen
	}

	port := int(uport)
	var tcp *net.TCPConn
	var fns []ReceiveFunc

	tcp, port, err = dialTcp("tcp4", bind.endpoint.IP, bind.endpoint.Port, port)
	if err != nil {
		return nil, 0, err
	}
	fns = append(fns, bind.makeReceiveFunc())
	bind.tcp = tcp
	return fns, uint16(port), nil
}

func (bind *StdNetBindTcp) Close() error {
	bind.mu.Lock()
	defer bind.mu.Unlock()

	var err error
	if bind.tls != nil {
		err = bind.tls.Close()
		bind.tls = nil
	}
	if bind.tcp != nil {
		err = bind.tcp.Close()
		bind.tcp = nil
	}
	return err
}

func (bind *StdNetBindTcp) getConn() (net.Conn, error) {
	bind.mu.Lock()
	defer bind.mu.Unlock()

	if !bind.useTls {
		return bind.tcp, nil
	}
	if bind.tls == nil && bind.tlsError == nil {
		bind.upgradeToTls()
	}
	return bind.tls, bind.tlsError
}

func (bind *StdNetBindTcp) makeReceiveFunc() ReceiveFunc {
	return func(buff []byte) (int, Endpoint, error) {
		var err error
		if bind.currentPacket == nil || bind.currentPacket.Len() == 0 {
			var conn net.Conn
			conn, err = bind.getConn()
			if err != nil {
				return 0, bind.endpoint, err
			}
			err = bind.readNextPacket(conn)
			if err != nil {
				return 0, bind.endpoint, err
			}
		}
		n, err := bind.currentPacket.Read(buff)
		if err != nil {
			return n, bind.endpoint, err
		}
		return n, bind.endpoint, err
	}
}

func (bind *StdNetBindTcp) readNextPacket(conn net.Conn) error {
	tunSafeHeader := make([]byte, tunSafeHeaderSize)
	_, err := io.ReadFull(conn, tunSafeHeader)
	if err != nil {
		return err
	}

	tunSafeType, payloadSize := parseTunSafeHeader(tunSafeHeader)
	wgPacket, offset, err := bind.tunsafe.prepareWgPacket(tunSafeType, payloadSize)
	if err != nil {
		return err
	}

	_, err = io.ReadFull(conn, wgPacket[offset:])
	if err != nil {
		return err
	}

	bind.tunsafe.onRecvPacket(tunSafeType, wgPacket)
	bind.currentPacket = bytes.NewReader(wgPacket)
	return nil
}

func (bind *StdNetBindTcp) Send(buff []byte, endpoint Endpoint) error {
	conn, err := bind.getConn()
	if err != nil {
		return err
	}

	// As single tcp socket can send only to single destination. We assume endpoint passed to ParseEndpoint will be
	// the same.
	if endpoint != bind.endpoint {
		return errors.New("StdNetBindTcp.Send endpoints mismatch")
	}

	tunSafePacket := bind.tunsafe.wgToTunSafe(buff)
	_, err = conn.Write(tunSafePacket)
	return err
}

func (bind *StdNetBindTcp) SetMark(_ uint32) error {
	return nil
}
