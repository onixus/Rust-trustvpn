// Reference AmneziaWG peer for interoperability tests: the official
// amneziawg-go device on a userspace network stack. It creates no TUN device
// and changes no routes; the only host socket is the UDP listener.
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/net/dns/dnsmessage"
)

const (
	server4 = "10.8.1.1"
	server6 = "fd00:8::1"
	mtu     = 1280
)

func random() (key [32]byte) {
	if _, err := rand.Read(key[:]); err != nil {
		log.Fatal(err)
	}
	return
}

func public(private [32]byte) (key [32]byte) {
	curve25519.ScalarBaseMult(&key, &private)
	return
}

func b64(key [32]byte) string { return base64.StdEncoding.EncodeToString(key[:]) }

// Server UAPI lines and the matching awg-quick lines of each mode.
func obfuscation(mode string, protection [32]byte) (string, string) {
	switch mode {
	case "plain":
		return "", ""
	case "awg2":
		return "jc=4\njmin=40\njmax=70\ns1=15\ns2=18\ns3=20\ns4=23\nh1=100000-200000\nh2=300000-400000\nh3=500000-600000\nh4=700000-800000\n",
			"Jc = 4\nJmin = 40\nJmax = 70\nS1 = 15\nS2 = 18\nS3 = 20\nS4 = 23\nH1 = 100000-200000\nH2 = 300000-400000\nH3 = 500000-600000\nH4 = 700000-800000\nI1 = <b 0xc0ffee><r 32><rc 8><rd 4><t>\nI2 = <r 64>\n"
	case "awg3":
		// With random trailers the reference classifies a datagram by its type
		// range alone, so the ranges stay narrow: a wide one would claim
		// transport packets as handshake messages.
		return "s1=33\ns2=12\ns3=40\ns4=17\nh1=1163027011-1163027074\nh2=2948113920-2948113983\nh3=377210880-377210911\nh4=3731148800-3731149055\n" +
				"header_protection_key=" + hex.EncodeToString(protection[:]) + "\ncontent_padding_addition=0-48\nrandom_trailers=true\ndisable_cookies=true\n",
			"Jc = 5\nJmin = 64\nJmax = 256\nS1 = 33\nS2 = 12\nS3 = 40\nS4 = 17\nH1 = 1163027011-1163027074\nH2 = 2948113920-2948113983\nH3 = 377210880-377210911\nH4 = 3731148800-3731149055\n" +
				"I1 = <b 0x16030100><r 48><t>\nHeaderProtectionKey = " + b64(protection) + "\nContentPaddingAddition = 16-96\nRandomTrailers = on\nDisableCookies = on\n" +
				// Short client-side timers so a test stream crosses several rekeys.
				"RekeyAfterTime = 3-5\nKeepaliveTimeout = 2-3\nRejectAfterTime = 30\n"
	}
	log.Fatalf("unknown mode %q", mode)
	return "", ""
}

func serveTCP(listener net.Listener) {
	for {
		stream, err := listener.Accept()
		if err != nil {
			return
		}
		go func() {
			defer stream.Close()
			var size uint32
			if binary.Read(stream, binary.BigEndian, &size) != nil || size > 64<<20 {
				return
			}
			digest := sha256.New()
			if _, err := io.CopyN(digest, stream, int64(size)); err != nil {
				return
			}
			fmt.Fprintf(stream, "%x", digest.Sum(nil))
		}()
	}
}

func serveEcho(socket net.PacketConn) {
	buffer := make([]byte, 65535)
	for {
		n, peer, err := socket.ReadFrom(buffer)
		if err != nil {
			return
		}
		socket.WriteTo(buffer[:n], peer)
	}
}

// Answers every A/AAAA question with the fixture's own address.
func serveDNS(socket net.PacketConn) {
	buffer := make([]byte, 1500)
	for {
		n, peer, err := socket.ReadFrom(buffer)
		if err != nil {
			return
		}
		var query dnsmessage.Message
		if query.Unpack(buffer[:n]) != nil || len(query.Questions) != 1 {
			continue
		}
		question := query.Questions[0]
		answer := dnsmessage.Message{
			Header:    dnsmessage.Header{ID: query.ID, Response: true, RecursionDesired: true, RecursionAvailable: true},
			Questions: query.Questions,
		}
		header := dnsmessage.ResourceHeader{Name: question.Name, Class: dnsmessage.ClassINET, TTL: 1}
		switch question.Type {
		case dnsmessage.TypeA:
			header.Type = dnsmessage.TypeA
			answer.Answers = []dnsmessage.Resource{{Header: header, Body: &dnsmessage.AResource{A: netip.MustParseAddr(server4).As4()}}}
		case dnsmessage.TypeAAAA:
			header.Type = dnsmessage.TypeAAAA
			answer.Answers = []dnsmessage.Resource{{Header: header, Body: &dnsmessage.AAAAResource{AAAA: netip.MustParseAddr(server6).As16()}}}
		}
		if packed, err := answer.Pack(); err == nil {
			socket.WriteTo(packed, peer)
		}
	}
}

func main() {
	if len(os.Args) != 3 {
		log.Fatal("usage: amneziawg_fixture plain|awg2|awg3 <client config path>")
	}
	mode, path := os.Args[1], os.Args[2]
	probe, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		log.Fatal(err)
	}
	port := probe.LocalAddr().(*net.UDPAddr).Port
	probe.Close()

	serverKey, clientKey, preshared, protection := random(), random(), random(), random()
	serverLines, clientLines := obfuscation(mode, protection)
	tun, network, err := netstack.CreateNetTUN(
		[]netip.Addr{netip.MustParseAddr(server4), netip.MustParseAddr(server6)}, nil, mtu)
	if err != nil {
		log.Fatal(err)
	}
	peer := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, ""))
	if err := peer.IpcSet(fmt.Sprintf("private_key=%x\nlisten_port=%d\n%spublic_key=%x\npreshared_key=%x\nallowed_ip=10.8.1.2/32\nallowed_ip=fd00:8::2/128\n",
		serverKey, port, serverLines, public(clientKey), preshared)); err != nil {
		log.Fatal(err)
	}
	if err := peer.Up(); err != nil {
		log.Fatal(err)
	}

	client := func(key [32]byte) string {
		return fmt.Sprintf("# AmneziaWG fixture %s\n[Interface]\nPrivateKey = %s\nAddress = 10.8.1.2/32, fd00:8::2/128\nDNS = %s\nMTU = %d\n%s\n[Peer]\nPublicKey = %s\nPresharedKey = %s\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = 127.0.0.1:%d\nPersistentKeepalive = 2-4\n",
			mode, b64(clientKey), server4, mtu, clientLines, b64(public(serverKey)), b64(key), port)
	}
	// The second profile differs only in the preshared key and must be rejected.
	for name, text := range map[string]string{path: client(preshared), path + ".rejected": client(random())} {
		if err := os.WriteFile(name, []byte(text), 0o600); err != nil {
			log.Fatal(err)
		}
	}

	tcp, err := network.ListenTCP(&net.TCPAddr{Port: 8080})
	if err != nil {
		log.Fatal(err)
	}
	echo, err := network.ListenUDP(&net.UDPAddr{Port: 7})
	if err != nil {
		log.Fatal(err)
	}
	dns, err := network.ListenUDP(&net.UDPAddr{Port: 53})
	if err != nil {
		log.Fatal(err)
	}
	go serveTCP(tcp)
	go serveEcho(echo)
	go serveDNS(dns)
	fmt.Println("ready")
	select {}
}
