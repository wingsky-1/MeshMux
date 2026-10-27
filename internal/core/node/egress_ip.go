package node

import (
	"net"
	"net/netip"
)

// egressProbe is an IANA TEST-NET address (RFC 5737). A UDP connect performs
// only a kernel route lookup: it sends no packet, contacts no service and does
// not require public connectivity. The selected local address is therefore the
// default route's source address, which is what the Hub uses as a display and
// default-fill value.
var egressProbe = net.IPv4(192, 0, 2, 1)

// LocalEgressIPv4 returns the IPv4 source address the default route selects,
// or an empty string when no IPv4 route is available. It never fails a
// heartbeat: an empty report is the same shape as an older Agent that does not
// report an address at all.
func LocalEgressIPv4() string {
	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: egressProbe, Port: 9})
	if err != nil {
		return ""
	}
	defer conn.Close()
	local, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return ""
	}
	addr, ok := netip.AddrFromSlice(local.IP)
	if !ok {
		return ""
	}
	addr = addr.Unmap()
	if !addr.Is4() || addr.IsUnspecified() {
		return ""
	}
	return addr.String()
}
