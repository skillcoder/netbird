//go:build android

package systemops

import (
	"context"
	"net"
	"net/netip"
	"runtime"

	log "github.com/sirupsen/logrus"

	nbnet "github.com/netbirdio/netbird/util/net"
)

func (r *SysOps) SetupRouting(context.Context, []net.IP) (nbnet.AddHookFunc, nbnet.RemoveHookFunc, error) {
	return nil, nil, nil
}

func (r *SysOps) CleanupRouting(context.Context) error {
	return nil
}

func (r *SysOps) AddVPNRoute(context.Context, netip.Prefix, *net.Interface) error {
	return nil
}

func (r *SysOps) RemoveVPNRoute(context.Context, netip.Prefix, *net.Interface) error {
	return nil
}

func EnableIPForwarding() error {
	log.Infof("Enable IP forwarding is not implemented on %s", runtime.GOOS)
	return nil
}

func IsAddrRouted(netip.Addr, []netip.Prefix) (bool, netip.Prefix) {
	return false, netip.Prefix{}
}
