// A conn.Bind listening on one address. The default bind listens on the
// wildcard address, and on a host with several interfaces its replies leave
// from the address of the outgoing interface rather than the one the client
// contacted; a client that only accepts its configured endpoint drops them.
package main

import (
	"net"
	"net/netip"
	"sync"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
)

type boundEndpoint netip.AddrPort

func (e boundEndpoint) ClearSrc()           {}
func (e boundEndpoint) SrcToString() string { return "" }
func (e boundEndpoint) DstToString() string { return netip.AddrPort(e).String() }
func (e boundEndpoint) DstToBytes() []byte {
	bytes, _ := netip.AddrPort(e).MarshalBinary()
	return bytes
}
func (e boundEndpoint) DstIP() netip.Addr { return netip.AddrPort(e).Addr() }
func (e boundEndpoint) SrcIP() netip.Addr { return netip.Addr{} }

type boundBind struct {
	address netip.Addr
	mutex   sync.Mutex
	socket  *net.UDPConn
}

func (b *boundBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	socket, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(b.address, port)))
	if err != nil {
		return nil, 0, err
	}
	b.socket = socket
	receive := func(packets [][]byte, sizes []int, endpoints []conn.Endpoint) (int, error) {
		n, peer, err := socket.ReadFromUDPAddrPort(packets[0])
		if err != nil {
			return 0, err
		}
		sizes[0] = n
		endpoints[0] = boundEndpoint(netip.AddrPortFrom(peer.Addr().Unmap(), peer.Port()))
		return 1, nil
	}
	return []conn.ReceiveFunc{receive}, uint16(socket.LocalAddr().(*net.UDPAddr).Port), nil
}

func (b *boundBind) Close() error {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	if b.socket == nil {
		return nil
	}
	err := b.socket.Close()
	b.socket = nil
	return err
}

func (b *boundBind) SetMark(uint32) error { return nil }
func (b *boundBind) BatchSize() int       { return 1 }

func (b *boundBind) Send(packets [][]byte, endpoint conn.Endpoint) error {
	b.mutex.Lock()
	socket := b.socket
	b.mutex.Unlock()
	if socket == nil {
		return net.ErrClosed
	}
	for _, packet := range packets {
		if _, err := socket.WriteToUDPAddrPort(packet, netip.AddrPort(endpoint.(boundEndpoint))); err != nil {
			return err
		}
	}
	return nil
}

func (b *boundBind) ParseEndpoint(text string) (conn.Endpoint, error) {
	address, err := netip.ParseAddrPort(text)
	return boundEndpoint(address), err
}
