package systemops

import (
	"net"
	"net/netip"
	"sync"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"

	"github.com/netbirdio/netbird/client/internal/routemanager/notifier"
	"github.com/netbirdio/netbird/client/internal/routemanager/refcounter"
	"github.com/netbirdio/netbird/iface"
)

type Nexthop struct {
	IP   netip.Addr
	Intf *net.Interface
}

func (nh Nexthop) String() string {
	if !nh.IP.IsValid() {
		return nh.Intf.Name
	}

	return nh.IP.String() + " " + nh.Intf.Name
}

type ExclusionCounter = refcounter.Counter[any, Nexthop]

type SysOps struct {
	refCounter  *ExclusionCounter
	wgInterface *iface.WGIface
	tracer      trace.Tracer
	// prefixes is tracking all the current added prefixes im memory
	// (this is used in iOS as all route updates require a full table update)
	//nolint
	prefixes map[netip.Prefix]struct{}
	//nolint
	mu sync.Mutex
	// notifier is used to notify the system of route changes (also used on mobile)
	notifier *notifier.Notifier
}

func NewSysOps(wgInterface *iface.WGIface, notifier *notifier.Notifier) *SysOps {
	return &SysOps{
		wgInterface: wgInterface,
		notifier:    notifier,
		tracer:      otel.Tracer("systemops"),
	}
}
