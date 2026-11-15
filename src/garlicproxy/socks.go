package garlicproxy

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"

	"github.com/yggdrasil-network/yggdrasil-go/src/garlic"
)

// SOCKS5 (RFC 1928) reply codes used here.
const (
	socksOK              = 0x00
	socksGeneralFailure  = 0x01
	socksNotAllowed      = 0x02
	socksHostUnreachable = 0x04
	socksRefused         = 0x05
	socksCmdUnsupported  = 0x07
	socksAtypUnsupported = 0x08
)

const socksDialTimeout = 90 * time.Second

// serveSOCKS runs one SOCKS5 session. Only CONNECT to a .domains.yggg name
// (ATYP 0x03) is accepted: IP literals, other names, BIND and UDP ASSOCIATE
// are refused, and nothing ever falls back to the ordinary network. The
// optional username/password (method 0x02) is accepted and ignored: Garlic
// has no per-credential circuit isolation yet.
func (p *Proxy) serveSOCKS(c net.Conn, br *bufio.Reader, release func()) {
	released := false
	done := func() {
		if !released {
			released = true
			release()
		}
	}
	defer done()
	_ = c.SetDeadline(time.Now().Add(handshakeTimeout))
	// Method selection.
	var head [2]byte
	if _, err := io.ReadFull(br, head[:]); err != nil || head[0] != 5 {
		return
	}
	methods := make([]byte, head[1])
	if _, err := io.ReadFull(br, methods); err != nil {
		return
	}
	method := byte(0xff)
	for _, m := range methods {
		if m == 0x00 {
			method = 0x00
			break
		}
		if m == 0x02 {
			method = 0x02
		}
	}
	if _, err := c.Write([]byte{5, method}); err != nil || method == 0xff {
		return
	}
	if method == 0x02 {
		// RFC 1929: VER=1 ULEN UNAME PLEN PASSWD. Any credentials pass.
		var v [2]byte
		if _, err := io.ReadFull(br, v[:1]); err != nil || v[0] != 1 {
			return
		}
		for range 2 { // username, then password: length byte + data
			if _, err := io.ReadFull(br, v[1:2]); err != nil {
				return
			}
			if _, err := io.CopyN(io.Discard, br, int64(v[1])); err != nil {
				return
			}
		}
		if _, err := c.Write([]byte{1, 0}); err != nil {
			return
		}
	}
	// Request.
	var req [4]byte
	if _, err := io.ReadFull(br, req[:]); err != nil || req[0] != 5 {
		return
	}
	var name string
	switch req[3] {
	case 0x01, 0x04:
		n := 4
		if req[3] == 0x04 {
			n = 16
		}
		if _, err := io.CopyN(io.Discard, br, int64(n+2)); err != nil {
			return
		}
		socksReply(c, socksNotAllowed)
		return
	case 0x03:
		var l [1]byte
		if _, err := io.ReadFull(br, l[:]); err != nil || l[0] == 0 {
			return
		}
		buf := make([]byte, int(l[0]))
		if _, err := io.ReadFull(br, buf); err != nil {
			return
		}
		name = string(buf)
	default:
		socksReply(c, socksAtypUnsupported)
		return
	}
	var pb [2]byte
	if _, err := io.ReadFull(br, pb[:]); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(pb[:])
	if req[1] != 0x01 { // BIND, UDP ASSOCIATE and the rest
		socksReply(c, socksCmdUnsupported)
		return
	}
	gid, err := garlic.ParseDomain(name)
	if err != nil {
		socksReply(c, socksNotAllowed)
		return
	}
	if port == 0 {
		socksReply(c, socksGeneralFailure)
		return
	}
	done() // the handshake is over; the slot is free while we dial and relay
	_ = c.SetDeadline(time.Time{})
	ctx, cancel := context.WithTimeout(p.ctx, socksDialTimeout)
	defer cancel()
	site, err := p.dial.DialService(ctx, gid.Domain(), port)
	if err != nil {
		socksReply(c, socksCode(err))
		return
	}
	defer site.Close()
	if !socksReply(c, socksOK) {
		return
	}
	relay(c, br, site)
}

// socksCode maps a DialService error to a SOCKS5 reply code: the port is
// not offered or its backend refuses -> 0x05; the service cannot be found or
// reached, or the attempt timed out -> 0x04; anything else -> 0x01.
func socksCode(err error) byte {
	switch {
	case errors.Is(err, garlic.ErrPortNotOffered), errors.Is(err, garlic.ErrBackendUnavailable):
		return socksRefused
	case isTimeout(err), errors.Is(err, garlic.ErrGIDNotFound), errors.Is(err, garlic.ErrDirectoryUnavailable), errors.Is(err, garlic.ErrNoTrustedPeers), errors.Is(err, garlic.ErrNoTrustedGuard):
		return socksHostUnreachable
	}
	return socksGeneralFailure
}

// socksReply sends a reply with BND.ADDR 0.0.0.0:0.
func socksReply(c net.Conn, code byte) bool {
	_, err := c.Write([]byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0})
	return err == nil
}
