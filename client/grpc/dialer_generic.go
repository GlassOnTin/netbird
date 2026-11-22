//go:build !js

package grpc

import (
	"context"
	"fmt"
	"net"
	"os/user"
	"runtime"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"

	nbnet "github.com/netbirdio/netbird/client/net"
)

func WithCustomDialer(_ bool, _ string) grpc.DialOption {
	return grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
		if runtime.GOOS == "android" {
			return dialPreferIPv4(ctx, addr)
		}
		if runtime.GOOS == "linux" {
			currentUser, err := user.Current()
			if err != nil {
				return nil, status.Errorf(codes.FailedPrecondition, "failed to get current user: %v", err)
			}

			// the custom dialer requires root permissions which are not required for use cases run as non-root
			if currentUser.Uid != "0" {
				log.Debug("Not running as root, using standard dialer")
				dialer := &net.Dialer{}
				return dialer.DialContext(ctx, "tcp", addr)
			}
		}

		conn, err := nbnet.NewDialer().DialContext(ctx, "tcp", addr)
		if err != nil {
			return nil, fmt.Errorf("nbnet.NewDialer().DialContext: %w", err)
		}
		return conn, nil
	})
}

// dialPreferIPv4 dials addr trying IPv4 first, then falling back to the normal
// (dual-stack/IPv6) netstack dialer.
//
// Android mobile networks frequently advertise IPv6 (RA / DNS64) while the
// IPv6 upstream is broken or filtered, and the platform resolver (netd, reached
// through cgo) can answer an AF_UNSPEC query with AAAA records only. The
// standard dual-stack dial then has no IPv4 candidate to fall back to and hangs
// on the dead IPv6 route until the gRPC context deadline expires — which is
// exactly the "create connection: dial context: context deadline exceeded"
// failure Haven saw joining the NetBird management service on mobile data
// (#662). Forcing an AF_INET ("ip4") lookup returns the A record even on an
// IPv6-preferred network, and the IPv4 path is reachable.
//
// IPv6-only networks still work: if the IPv4 lookup or dial fails we fall back
// to the standard dialer, which resolves and dials IPv6.
func dialPreferIPv4(ctx context.Context, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nbnet.NewDialer().DialContext(ctx, "tcp", addr)
	}
	// An IP literal needs no resolution; dial it directly.
	if net.ParseIP(host) != nil {
		return nbnet.NewDialer().DialContext(ctx, "tcp", addr)
	}

	ips, lookupErr := net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
	log.Debugf("prefer-IPv4 dial %s: ip4 lookup=%v err=%v", addr, ips, lookupErr)
	if lookupErr == nil {
		for _, ip := range ips {
			conn, dialErr := nbnet.NewDialer().DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), port))
			if dialErr == nil {
				return conn, nil
			}
			log.Debugf("prefer-IPv4 dial %s via %s failed: %v", addr, ip, dialErr)
		}
	}
	// No usable IPv4 — fall back to the standard (IPv6) dial.
	return nbnet.NewDialer().DialContext(ctx, "tcp", addr)
}
