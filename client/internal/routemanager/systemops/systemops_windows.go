//go:build windows

package systemops

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/yusufpapurcu/wmi"

	"github.com/netbirdio/netbird/client/firewall/uspfilter"
	nbnet "github.com/netbirdio/netbird/util/net"
)

type MSFT_NetRoute struct {
	DestinationPrefix string
	NextHop           string
	InterfaceIndex    int32
	InterfaceAlias    string
	AddressFamily     uint16
}

type Route struct {
	Destination netip.Prefix
	Nexthop     netip.Addr
	Interface   *net.Interface
}

type MSFT_NetNeighbor struct {
	IPAddress        string
	LinkLayerAddress string
	State            uint8
	AddressFamily    uint16
	InterfaceIndex   uint32
	InterfaceAlias   string
}

type Neighbor struct {
	IPAddress        netip.Addr
	LinkLayerAddress string
	State            uint8
	AddressFamily    uint16
	InterfaceIndex   uint32
	InterfaceAlias   string
}

var prefixList []netip.Prefix
var lastUpdate time.Time
var mux = sync.Mutex{}

func (r *SysOps) SetupRouting(ctx context.Context, initAddresses []net.IP) (nbnet.AddHookFunc, nbnet.RemoveHookFunc, error) {
	return r.setupRefCounter(ctx, initAddresses)
}

func (r *SysOps) CleanupRouting(ctx context.Context) error {
	return r.cleanupRefCounter(ctx)
}

func (r *SysOps) addToRouteTable(_ context.Context, prefix netip.Prefix, nexthop Nexthop) error {
	if nexthop.IP.Zone() != "" && nexthop.Intf == nil {
		zone, err := strconv.Atoi(nexthop.IP.Zone())
		if err != nil {
			return fmt.Errorf("invalid zone: %w", err)
		}
		nexthop.Intf = &net.Interface{Index: zone}
	}

	return addRouteCmd(prefix, nexthop)
}

func (r *SysOps) removeFromRouteTable(ctx context.Context, prefix netip.Prefix, nexthop Nexthop) error {
	args := []string{"delete", prefix.String()}
	if nexthop.IP.IsValid() {
		ip := nexthop.IP.WithZone("")
		args = append(args, ip.Unmap().String())
	}

	routeCmd := uspfilter.GetSystem32Command("route")

	out, err := exec.Command(routeCmd, args...).CombinedOutput()
	log.Tracef("route %s: %s", strings.Join(args, " "), out)

	if err != nil {
		return fmt.Errorf("remove route: %w", err)
	}
	return nil
}

func GetRoutesFromTable() ([]netip.Prefix, error) {
	mux.Lock()
	defer mux.Unlock()

	// If many routes are added at the same time this might block for a long time (seconds to minutes), so we cache the result
	if !isCacheDisabled() && time.Since(lastUpdate) < 2*time.Second {
		return prefixList, nil
	}

	routes, err := GetRoutes()
	if err != nil {
		return nil, fmt.Errorf("get routes: %w", err)
	}

	prefixList = nil
	for _, route := range routes {
		prefixList = append(prefixList, route.Destination)
	}

	lastUpdate = time.Now()
	return prefixList, nil
}

func GetRoutes() ([]Route, error) {
	var entries []MSFT_NetRoute

	query := `SELECT DestinationPrefix, Nexthop, InterfaceIndex, InterfaceAlias, AddressFamily FROM MSFT_NetRoute`
	if err := wmi.QueryNamespace(query, &entries, `ROOT\StandardCimv2`); err != nil {
		return nil, fmt.Errorf("get routes: %w", err)
	}

	var routes []Route
	for _, entry := range entries {
		dest, err := netip.ParsePrefix(entry.DestinationPrefix)
		if err != nil {
			log.Warnf("Unable to parse route destination %s: %v", entry.DestinationPrefix, err)
			continue
		}

		nexthop, err := netip.ParseAddr(entry.NextHop)
		if err != nil {
			log.Warnf("Unable to parse route next hop %s: %v", entry.NextHop, err)
			continue
		}

		var intf *net.Interface
		if entry.InterfaceIndex != 0 {
			intf = &net.Interface{
				Index: int(entry.InterfaceIndex),
				Name:  entry.InterfaceAlias,
			}

			if nexthop.Is6() && (nexthop.IsLinkLocalUnicast() || nexthop.IsLinkLocalMulticast()) {
				nexthop = nexthop.WithZone(strconv.Itoa(int(entry.InterfaceIndex)))
			}
		}

		routes = append(routes, Route{
			Destination: dest,
			Nexthop:     nexthop,
			Interface:   intf,
		})
	}

	return routes, nil
}

func GetNeighbors() ([]Neighbor, error) {
	var entries []MSFT_NetNeighbor
	query := `SELECT IPAddress, LinkLayerAddress, State, AddressFamily, InterfaceIndex, InterfaceAlias FROM MSFT_NetNeighbor`
	if err := wmi.QueryNamespace(query, &entries, `ROOT\StandardCimv2`); err != nil {
		return nil, fmt.Errorf("failed to query MSFT_NetNeighbor: %w", err)
	}

	var neighbors []Neighbor
	for _, entry := range entries {
		addr, err := netip.ParseAddr(entry.IPAddress)
		if err != nil {
			log.Warnf("Unable to parse neighbor IP address %s: %v", entry.IPAddress, err)
			continue
		}
		neighbors = append(neighbors, Neighbor{
			IPAddress:        addr,
			LinkLayerAddress: entry.LinkLayerAddress,
			State:            entry.State,
			AddressFamily:    entry.AddressFamily,
			InterfaceIndex:   entry.InterfaceIndex,
			InterfaceAlias:   entry.InterfaceAlias,
		})
	}

	return neighbors, nil
}

func addRouteCmd(prefix netip.Prefix, nexthop Nexthop) error {
	args := []string{"add", prefix.String()}

	if nexthop.IP.IsValid() {
		ip := nexthop.IP.WithZone("")
		args = append(args, ip.Unmap().String())
	} else {
		addr := "0.0.0.0"
		if prefix.Addr().Is6() {
			addr = "::"
		}
		args = append(args, addr)
	}

	if nexthop.Intf != nil {
		args = append(args, "if", strconv.Itoa(nexthop.Intf.Index))
	}

	routeCmd := uspfilter.GetSystem32Command("route")

	out, err := exec.Command(routeCmd, args...).CombinedOutput()
	log.Tracef("route %s: %s", strings.Join(args, " "), out)
	if err != nil {
		return fmt.Errorf("route add: %w", err)
	}

	return nil
}

func isCacheDisabled() bool {
	return os.Getenv("NB_DISABLE_ROUTE_CACHE") == "true"
}
