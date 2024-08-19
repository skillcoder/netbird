//go:build !linux && !ios

package systemops

import (
	"context"
	"net"
	"net/netip"
	"runtime"

	log "github.com/sirupsen/logrus"
)

func (r *SysOps) AddVPNRoute(ctx context.Context, prefix netip.Prefix, intf *net.Interface) error {
	return r.genericAddVPNRoute(ctx, prefix, intf)
}

func (r *SysOps) RemoveVPNRoute(ctx context.Context, prefix netip.Prefix, intf *net.Interface) error {
	return r.genericRemoveVPNRoute(ctx, prefix, intf)
}

func EnableIPForwarding() error {
	log.Infof("Enable IP forwarding is not implemented on %s", runtime.GOOS)
	return nil
}

func hasSeparateRouting() ([]netip.Prefix, error) {
	return GetRoutesFromTable()
}
