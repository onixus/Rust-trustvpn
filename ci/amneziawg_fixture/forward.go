// A tun.Device that terminates every TCP and UDP flow of the tunnel in a
// userspace stack and relays it through ordinary sockets of this process: a
// NAT gateway without a TUN device, routes or privileges. The device plumbing
// follows amneziawg-go's tun/netstack (MIT).
package main

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"syscall"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const udpIdle = 60 * time.Second

type forwardTun struct {
	endpoint *channel.Endpoint
	stack    *stack.Stack
	events   chan tun.Event
	incoming chan *buffer.View
	notify   *channel.NotificationHandle
	mtu      int
}

// loopbackAlias, when set, is a tunnel destination relayed to 127.0.0.1. The
// userspace stack drops packets addressed to loopback itself, and a test on
// one machine must not depend on that machine's network.
var loopbackAlias netip.Addr

func target(id stack.TransportEndpointID) string {
	address, _ := netip.AddrFromSlice(id.LocalAddress.AsSlice())
	address = address.Unmap()
	if address == loopbackAlias {
		address = netip.AddrFrom4([4]byte{127, 0, 0, 1})
	}
	return net.JoinHostPort(address.String(), strconv.Itoa(int(id.LocalPort)))
}

func newForwardTun(mtu int) (tun.Device, error) {
	device := &forwardTun{
		endpoint: channel.New(1024, uint32(mtu), ""),
		stack: stack.New(stack.Options{
			NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
			TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
		}),
		events:   make(chan tun.Event, 10),
		incoming: make(chan *buffer.View),
		mtu:      mtu,
	}
	fail := func(err tcpip.Error) (tun.Device, error) { return nil, errors.New(err.String()) }
	sack := tcpip.TCPSACKEnabled(true)
	if err := device.stack.SetTransportProtocolOption(tcp.ProtocolNumber, &sack); err != nil {
		return fail(err)
	}
	device.notify = device.endpoint.AddNotify(device)
	if err := device.stack.CreateNIC(1, device.endpoint); err != nil {
		return fail(err)
	}
	// Accept packets for any destination and answer from that address.
	if err := device.stack.SetPromiscuousMode(1, true); err != nil {
		return fail(err)
	}
	if err := device.stack.SetSpoofing(1, true); err != nil {
		return fail(err)
	}
	device.stack.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: 1},
		{Destination: header.IPv6EmptySubnet, NIC: 1},
	})

	streams := tcp.NewForwarder(device.stack, 0, 1024, func(request *tcp.ForwarderRequest) {
		// Dial first: a refused destination must reset the tunnel connection.
		outside, err := net.DialTimeout("tcp", target(request.ID()), 5*time.Second)
		if err != nil {
			request.Complete(true)
			return
		}
		var queue waiter.Queue
		endpoint, failure := request.CreateEndpoint(&queue)
		if failure != nil {
			outside.Close()
			request.Complete(true)
			return
		}
		request.Complete(false)
		inside := gonet.NewTCPConn(&queue, endpoint)
		go func() {
			io.Copy(outside, inside)
			outside.(*net.TCPConn).CloseWrite()
		}()
		go func() {
			io.Copy(inside, outside)
			inside.CloseWrite()
			// Both directions are done once the client closes too.
			time.AfterFunc(udpIdle, func() { inside.Close(); outside.Close() })
		}()
	})
	device.stack.SetTransportProtocolHandler(tcp.ProtocolNumber, streams.HandlePacket)

	datagrams := udp.NewForwarder(device.stack, func(request *udp.ForwarderRequest) {
		var queue waiter.Queue
		endpoint, failure := request.CreateEndpoint(&queue)
		if failure != nil {
			return
		}
		inside := gonet.NewUDPConn(device.stack, &queue, endpoint)
		destination := target(request.ID())
		go func() {
			outside, err := net.Dial("udp", destination)
			if err != nil {
				inside.Close()
				return
			}
			relay := func(to, from net.Conn) {
				defer to.Close()
				defer from.Close()
				packet := make([]byte, 65535)
				for {
					from.SetReadDeadline(time.Now().Add(udpIdle))
					n, err := from.Read(packet)
					if err != nil {
						return
					}
					to.Write(packet[:n])
				}
			}
			go relay(outside, inside)
			relay(inside, outside)
		}()
	})
	device.stack.SetTransportProtocolHandler(udp.ProtocolNumber, datagrams.HandlePacket)

	device.events <- tun.EventUp
	return device, nil
}

func (device *forwardTun) Name() (string, error)    { return "forward", nil }
func (device *forwardTun) File() *os.File           { return nil }
func (device *forwardTun) Events() <-chan tun.Event { return device.events }
func (device *forwardTun) MTU() (int, error)        { return device.mtu, nil }
func (device *forwardTun) BatchSize() int           { return 1 }

func (device *forwardTun) Read(buffers [][]byte, sizes []int, offset int) (int, error) {
	view, ok := <-device.incoming
	if !ok {
		return 0, os.ErrClosed
	}
	n, err := view.Read(buffers[0][offset:])
	if err != nil {
		return 0, err
	}
	sizes[0] = n
	return 1, nil
}

func (device *forwardTun) Write(buffers [][]byte, offset int) (int, error) {
	for _, data := range buffers {
		packet := data[offset:]
		if len(packet) == 0 {
			continue
		}
		wrapped := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(packet)})
		switch packet[0] >> 4 {
		case 4:
			device.endpoint.InjectInbound(header.IPv4ProtocolNumber, wrapped)
		case 6:
			device.endpoint.InjectInbound(header.IPv6ProtocolNumber, wrapped)
		default:
			return 0, syscall.EAFNOSUPPORT
		}
	}
	return len(buffers), nil
}

func (device *forwardTun) WriteNotify() {
	packet := device.endpoint.Read()
	if packet == nil {
		return
	}
	view := packet.ToView()
	packet.DecRef()
	device.incoming <- view
}

func (device *forwardTun) Close() error {
	device.stack.RemoveNIC(1)
	device.stack.Close()
	device.endpoint.RemoveNotify(device.notify)
	device.endpoint.Close()
	close(device.events)
	close(device.incoming)
	return nil
}
