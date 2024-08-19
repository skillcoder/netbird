//go:build !android && !ios

package systemops

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"testing"

	"github.com/pion/transport/v3/stdnet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/iface"
)

type dialer interface {
	Dial(network, address string) (net.Conn, error)
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

func TestAddRemoveRoutes(t *testing.T) {
	testCases := []struct {
		name                   string
		prefix                 netip.Prefix
		shouldRouteToWireguard bool
		shouldBeRemoved        bool
	}{
		{
			name:                   "Should Add And Remove Route 100.66.120.0/24",
			prefix:                 netip.MustParsePrefix("100.66.120.0/24"),
			shouldRouteToWireguard: true,
			shouldBeRemoved:        true,
		},
		{
			name:                   "Should Not Add Or Remove Route 127.0.0.1/32",
			prefix:                 netip.MustParsePrefix("127.0.0.1/32"),
			shouldRouteToWireguard: false,
			shouldBeRemoved:        false,
		},
	}

	for n, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Setenv("NB_DISABLE_ROUTE_CACHE", "true")

			ctx := context.Background()

			peerPrivateKey, _ := wgtypes.GeneratePrivateKey()
			newNet, err := stdnet.NewNet()
			if err != nil {
				t.Fatal(err)
			}
			wgInterface, err := iface.NewWGIFace(fmt.Sprintf("utun53%d", n), "100.65.73.2/24", 33103, peerPrivateKey.String(), iface.DefaultMTU, newNet, nil, nil)
			require.NoError(t, err, "should create testing WGIface interface")
			defer wgInterface.Close()

			err = wgInterface.Create()
			require.NoError(t, err, "should create testing wireguard interface")

			r := NewSysOps(wgInterface, nil)

			_, _, err = r.SetupRouting(ctx, nil)
			require.NoError(t, err)
			t.Cleanup(func() {
				assert.NoError(t, r.CleanupRouting(ctx))
			})

			index, err := net.InterfaceByName(wgInterface.Name())
			require.NoError(t, err, "InterfaceByName should not return err")
			intf := &net.Interface{Index: index.Index, Name: wgInterface.Name()}

			err = r.AddVPNRoute(ctx, testCase.prefix, intf)
			require.NoError(t, err, "genericAddVPNRoute should not return err")

			if testCase.shouldRouteToWireguard {
				assertWGOutInterface(t, testCase.prefix, wgInterface, false)
			} else {
				assertWGOutInterface(t, testCase.prefix, wgInterface, true)
			}
			exists, err := existsInRouteTable(testCase.prefix)
			require.NoError(t, err, "existsInRouteTable should not return err")
			if exists && testCase.shouldRouteToWireguard {
				err = r.RemoveVPNRoute(ctx, testCase.prefix, intf)
				require.NoError(t, err, "genericRemoveVPNRoute should not return err")

				prefixNexthop, err := GetNextHop(testCase.prefix.Addr())
				require.NoError(t, err, "GetNextHop should not return err")

				internetNexthop, err := GetNextHop(netip.MustParseAddr("0.0.0.0"))
				require.NoError(t, err)

				if testCase.shouldBeRemoved {
					require.Equal(t, internetNexthop.IP, prefixNexthop.IP, "route should be pointing to default internet gateway")
				} else {
					require.NotEqual(t, internetNexthop.IP, prefixNexthop.IP, "route should be pointing to a different gateway than the internet gateway")
				}
			}
		})
	}
}

func TestGetNextHop(t *testing.T) {
	nexthop, err := GetNextHop(netip.MustParseAddr("0.0.0.0"))
	if err != nil {
		t.Fatal("shouldn't return error when fetching the gateway: ", err)
	}
	if !nexthop.IP.IsValid() {
		t.Fatal("should return a gateway")
	}
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal("shouldn't return error when fetching interface addresses: ", err)
	}

	var testingIP string
	var testingPrefix netip.Prefix
	for _, address := range addresses {
		if address.Network() != "ip+net" {
			continue
		}
		prefix := netip.MustParsePrefix(address.String())
		if !prefix.Addr().IsLoopback() && prefix.Addr().Is4() {
			testingIP = prefix.Addr().String()
			testingPrefix = prefix.Masked()
			break
		}
	}

	localIP, err := GetNextHop(testingPrefix.Addr())
	if err != nil {
		t.Fatal("shouldn't return error: ", err)
	}
	if !localIP.IP.IsValid() {
		t.Fatal("should return a gateway for local network")
	}
	if localIP.IP.String() == nexthop.IP.String() {
		t.Fatal("local IP should not match with gateway IP")
	}
	if localIP.IP.String() != testingIP {
		t.Fatalf("local IP should match with testing IP: want %s got %s", testingIP, localIP.IP.String())
	}
}

// NOTE: this test can't run in parallel with outer routing tests, since we check system shared route table
func TestAddExistAndRemoveRoute(t *testing.T) {
	defaultNexthop, err := GetNextHop(netip.MustParseAddr("0.0.0.0"))
	t.Log("defaultNexthop: ", defaultNexthop)
	if err != nil {
		t.Fatal("shouldn't return error when fetching the gateway: ", err)
	}

	testCases := []struct {
		name              string
		prefix            netip.Prefix
		preExistingPrefix netip.Prefix
	}{
		{
			name:   "Should Add And Remove random Route",
			prefix: netip.MustParsePrefix("99.99.99.99/32"),
		},
		{
			name:              "Should Add Route if bigger network exists",
			prefix:            netip.MustParsePrefix("100.100.100.0/24"),
			preExistingPrefix: netip.MustParsePrefix("100.100.0.0/16"),
		},
		{
			name:              "Should Add Route if smaller network exists",
			prefix:            netip.MustParsePrefix("100.100.0.0/16"),
			preExistingPrefix: netip.MustParsePrefix("100.100.100.0/24"),
		},
		{
			name:              "Should Add only prefix route if overlaps with default gateway if route alredy exist",
			prefix:            netip.MustParsePrefix(defaultNexthop.IP.String() + "/31"),
			preExistingPrefix: netip.MustParsePrefix(defaultNexthop.IP.String() + "/32"),
		},
	}

	for n, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Setenv("NB_USE_LEGACY_ROUTING", "true")
			t.Setenv("NB_DISABLE_ROUTE_CACHE", "true")

			ctx := context.Background()

			initialRoutes, err := GetRoutesFromTable()
			if err != nil {
				t.Fatal(err, "GetRoutesFromTable")
			}

			expectedRoutesCount := len(initialRoutes)

			peerPrivateKey, _ := wgtypes.GeneratePrivateKey()
			newNet, err := stdnet.NewNet()
			if err != nil {
				t.Fatal(err, "stdnet.NewNet")
			}

			wgInterface, err := iface.NewWGIFace(fmt.Sprintf("utun54%d", n), "100.65.74.2/24", 33104, peerPrivateKey.String(), iface.DefaultMTU, newNet, nil, nil)
			require.NoError(t, err, "should create testing WGIface interface")
			defer wgInterface.Close()

			err = wgInterface.Create()
			require.NoError(t, err, "should create testing wireguard interface")

			index, err := net.InterfaceByName(wgInterface.Name())
			require.NoError(t, err, "InterfaceByName should not return err")
			intf := &net.Interface{Index: index.Index, Name: wgInterface.Name()}

			r := NewSysOps(wgInterface, nil)

			// Check testing environment
			// Every routes we using in this our tests should not exist
			ok, err := existsInRouteTable(testCase.prefix)
			require.NoError(t, err, "should not return err")
			require.False(t, ok, "testing route should not exist before the test: %s", testCase.prefix)

			// Prepare the environment
			if testCase.preExistingPrefix.IsValid() {
				ok, err := existsInRouteTable(testCase.preExistingPrefix)
				require.NoError(t, err, "should not return err")
				require.False(t, ok, "preExistingPrefix route should not exist before the test: %s", testCase.preExistingPrefix)

				err = r.AddVPNRoute(ctx, testCase.preExistingPrefix, intf)
				require.NoError(t, err, "should not return err when adding pre-existing route")

				routes, err := GetRoutesFromTable()
				require.NoError(t, err, "preExistingPrefix GetRoutesFromTable should not return err")
				expectedRoutesCount++
				require.Equal(t, expectedRoutesCount, len(routes))
			}

			// Add the route
			err = r.AddVPNRoute(ctx, testCase.prefix, intf)
			require.NoError(t, err, "should not return err when adding route")

			routes, err := GetRoutesFromTable()
			require.NoError(t, err, "add GetRoutesFromTable should not return err")
			expectedRoutesCount++
			require.Equal(t, expectedRoutesCount, len(routes))

			// test if route exists after adding
			ok, err = existsInRouteTable(testCase.prefix)
			require.NoError(t, err, "should not return err")
			require.True(t, ok, "route should exist")

			// remove route again if added
			err = r.RemoveVPNRoute(ctx, testCase.prefix, intf)
			require.NoError(t, err, "should not return err")

			routes, err = GetRoutesFromTable()
			require.NoError(t, err, "delete GetRoutesFromTable should not return err")
			expectedRoutesCount--
			require.Equal(t, expectedRoutesCount, len(routes))

			// route should either not have been added or should have been removed
			// In case of already existing route, it should not have been added (but still exist)
			ok, err = existsInRouteTable(testCase.prefix)
			require.NoError(t, err, "should not return err")
			require.False(t, ok, "route should not exist: %s", testCase.prefix)
		})
	}
}

func TestShouldNotAddRoute(t *testing.T) {
	testCases := []struct {
		name              string
		prefix            netip.Prefix
		preExistingPrefix netip.Prefix
	}{
		{
			name:              "Should Not Add Route if same network exists",
			prefix:            netip.MustParsePrefix("100.100.0.0/16"),
			preExistingPrefix: netip.MustParsePrefix("100.100.0.0/16"),
		},
	}

	for n, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Setenv("NB_USE_LEGACY_ROUTING", "true")
			t.Setenv("NB_DISABLE_ROUTE_CACHE", "true")

			exporter, cleanup := setupInMemoryTracer()
			defer cleanup()

			ctx := context.Background()

			peerPrivateKey, _ := wgtypes.GeneratePrivateKey()
			newNet, err := stdnet.NewNet()
			if err != nil {
				t.Fatal(err)
			}

			wgInterface, err := iface.NewWGIFace(fmt.Sprintf("utun56%d", n), "100.65.76.2/24", 33106, peerPrivateKey.String(), iface.DefaultMTU, newNet, nil, nil)
			require.NoError(t, err, "should create testing WGIface interface")
			defer wgInterface.Close()

			err = wgInterface.Create()
			require.NoError(t, err, "should create testing wireguard interface")

			index, err := net.InterfaceByName(wgInterface.Name())
			require.NoError(t, err, "InterfaceByName should not return err")
			intf := &net.Interface{Index: index.Index, Name: wgInterface.Name()}

			r := NewSysOps(wgInterface, nil)

			// Check testing environment
			// Every routes we using in this our tests should not exist
			ok, err := existsInRouteTable(testCase.prefix)
			require.NoError(t, err, "should not return err")
			require.False(t, ok, "testing route should not exist before the test: %s", testCase.prefix)

			// Prepare the environment
			if testCase.preExistingPrefix.IsValid() {
				ok, err := existsInRouteTable(testCase.preExistingPrefix)
				require.NoError(t, err, "should not return err")
				require.False(t, ok, "preExistingPrefix route should not exist before the test: %s", testCase.preExistingPrefix)

				err = r.AddVPNRoute(ctx, testCase.preExistingPrefix, intf)
				require.NoError(t, err, "should not return err when adding pre-existing route")
			}

			// Add the route
			err = r.AddVPNRoute(ctx, testCase.prefix, intf)
			require.NoError(t, err, "should not return err when adding route")

			// route should either not have been added or should have been removed
			// In case of already existing route, it should not have been added (but still exist)
			ok, err = existsInRouteTable(testCase.prefix)
			require.NoError(t, err, "should not return err")
			if testCase.preExistingPrefix.IsValid() {
				// Retrieve the spans from the exporter
				spans := exporter.GetSpans()
				require.Equal(t, 1, len(spans), "should have tracing spans")
				require.Equal(t, "addNonExistingRoute", spans[0].Name)
				require.True(t, hasAttributeName(spans[0], "skipped-exist"))
				// require.Equal(t, "addRouteForCurrentDefaultGateway", spans[1].Name)

				// cleanup
				err = r.RemoveVPNRoute(ctx, testCase.preExistingPrefix, intf)
				require.NoError(t, err, "should not return err")

				// route should have been removed, to restore previous state
				ok, err = existsInRouteTable(testCase.preExistingPrefix)
				require.NoError(t, err, "should not return err")
				require.False(t, ok, "route should not exist: %s", testCase.preExistingPrefix)
			} else {
				require.False(t, ok, "route should not exist: %s", testCase.prefix)
			}
		})
	}
}

func TestIsSubRange(t *testing.T) {
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal("shouldn't return error when fetching interface addresses: ", err)
	}

	var subRangeAddressPrefixes []netip.Prefix
	var nonSubRangeAddressPrefixes []netip.Prefix
	for _, address := range addresses {
		p := netip.MustParsePrefix(address.String())
		if !p.Addr().IsLoopback() && p.Addr().Is4() && p.Bits() < 32 {
			p2 := netip.PrefixFrom(p.Masked().Addr(), p.Bits()+1)
			subRangeAddressPrefixes = append(subRangeAddressPrefixes, p2)
			nonSubRangeAddressPrefixes = append(nonSubRangeAddressPrefixes, p.Masked())
		}
	}

	for _, prefix := range subRangeAddressPrefixes {
		isSubRangePrefix, err := isSubRange(prefix)
		if err != nil {
			t.Fatal("shouldn't return error when checking if address is sub-range: ", err)
		}
		if !isSubRangePrefix {
			t.Fatalf("address %s should be sub-range of an existing route in the table", prefix)
		}
	}

	for _, prefix := range nonSubRangeAddressPrefixes {
		isSubRangePrefix, err := isSubRange(prefix)
		if err != nil {
			t.Fatal("shouldn't return error when checking if address is sub-range: ", err)
		}
		if isSubRangePrefix {
			t.Fatalf("address %s should not be sub-range of an existing route in the table", prefix)
		}
	}
}

func TestExistsInRouteTable(t *testing.T) {
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal("shouldn't return error when fetching interface addresses: ", err)
	}

	var addressPrefixes []netip.Prefix
	for _, address := range addresses {
		p := netip.MustParsePrefix(address.String())

		switch {
		case p.Addr().Is6():
			continue
		// Windows sometimes has hidden interface link local addrs that don't turn up on any interface
		case runtime.GOOS == "windows" && p.Addr().IsLinkLocalUnicast():
			continue
		// Linux loopback 127/8 is in the local table, not in the main table and always takes precedence
		case runtime.GOOS == "linux" && p.Addr().IsLoopback():
			continue
		// FreeBSD loopback 127/8 is not added to the routing table
		case runtime.GOOS == "freebsd" && p.Addr().IsLoopback():
			continue
		default:
			addressPrefixes = append(addressPrefixes, p.Masked())
		}
	}

	for _, prefix := range addressPrefixes {
		exists, err := existsInRouteTable(prefix)
		if err != nil {
			t.Fatal("shouldn't return error when checking if address exists in route table: ", err)
		}
		if !exists {
			t.Fatalf("address %s should exist in route table", prefix)
		}
	}
}

func createWGInterface(t *testing.T, interfaceName, ipAddressCIDR string, listenPort int) *iface.WGIface {
	t.Helper()

	peerPrivateKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)

	newNet, err := stdnet.NewNet()
	require.NoError(t, err)

	wgInterface, err := iface.NewWGIFace(interfaceName, ipAddressCIDR, listenPort, peerPrivateKey.String(), iface.DefaultMTU, newNet, nil, nil)
	require.NoError(t, err, "should create testing WireGuard interface")

	err = wgInterface.Create()
	require.NoError(t, err, "should create testing WireGuard interface")

	t.Cleanup(func() {
		wgInterface.Close()
	})

	return wgInterface
}

func setupRouteAndCleanup(ctx context.Context, t *testing.T, r *SysOps, prefix netip.Prefix, intf *net.Interface) {
	t.Helper()

	err := r.AddVPNRoute(ctx, prefix, intf)
	require.NoError(t, err, "addVPNRoute should not return err: %s %s", prefix.String(), intf.Name)
	t.Cleanup(func() {
		err = r.RemoveVPNRoute(ctx, prefix, intf)
		assert.NoError(t, err, "removeVPNRoute should not return err: %s %s", prefix.String(), intf.Name)
	})
}

func setupTestEnv(ctx context.Context, t *testing.T) {
	t.Helper()

	setupDummyInterfacesAndRoutes(t)

	wgInterface := createWGInterface(t, expectedVPNint, "100.64.0.1/24", 51820)
	t.Cleanup(func() {
		assert.NoError(t, wgInterface.Close())
	})

	r := NewSysOps(wgInterface, nil)
	_, _, err := r.SetupRouting(ctx, nil)
	require.NoError(t, err, "setupRouting should not return err")
	t.Cleanup(func() {
		assert.NoError(t, r.CleanupRouting(ctx))
	})

	index, err := net.InterfaceByName(wgInterface.Name())
	require.NoError(t, err, "InterfaceByName should not return err")
	intf := &net.Interface{Index: index.Index, Name: wgInterface.Name()}

	// default route exists in main table and vpn table
	setupRouteAndCleanup(ctx, t, r, netip.MustParsePrefix("0.0.0.0/0"), intf)

	// 10.0.0.0/8 route exists in main table and vpn table
	setupRouteAndCleanup(ctx, t, r, netip.MustParsePrefix("10.0.0.0/8"), intf)

	// 10.10.0.0/24 more specific route exists in vpn table
	setupRouteAndCleanup(ctx, t, r, netip.MustParsePrefix("10.10.0.0/24"), intf)

	// 127.0.10.0/24 more specific route exists in vpn table
	setupRouteAndCleanup(ctx, t, r, netip.MustParsePrefix("127.0.10.0/24"), intf)

	// unique route in vpn table
	setupRouteAndCleanup(ctx, t, r, netip.MustParsePrefix("172.16.0.0/12"), intf)
}

func assertWGOutInterface(t *testing.T, prefix netip.Prefix, wgIface *iface.WGIface, invert bool) {
	t.Helper()
	if runtime.GOOS == "linux" && prefix.Addr().IsLoopback() {
		return
	}

	prefixNexthop, err := GetNextHop(prefix.Addr())
	require.NoError(t, err, "GetNextHop should not return err")
	if invert {
		assert.NotEqual(t, wgIface.Address().IP.String(), prefixNexthop.IP.String(), "route should not point to wireguard interface IP")
	} else {
		assert.Equal(t, wgIface.Address().IP.String(), prefixNexthop.IP.String(), "route should point to wireguard interface IP")
	}
}

func TestIsVpnRoute(t *testing.T) {
	tests := []struct {
		name           string
		addr           string
		vpnRoutes      []string
		localRoutes    []string
		expectedVpn    bool
		expectedPrefix netip.Prefix
	}{
		{
			name:           "Match in VPN routes",
			addr:           "192.168.1.1",
			vpnRoutes:      []string{"192.168.1.0/24"},
			localRoutes:    []string{"10.0.0.0/8"},
			expectedVpn:    true,
			expectedPrefix: netip.MustParsePrefix("192.168.1.0/24"),
		},
		{
			name:           "Match in local routes",
			addr:           "10.1.1.1",
			vpnRoutes:      []string{"192.168.1.0/24"},
			localRoutes:    []string{"10.0.0.0/8"},
			expectedVpn:    false,
			expectedPrefix: netip.MustParsePrefix("10.0.0.0/8"),
		},
		{
			name:           "No match",
			addr:           "172.16.0.1",
			vpnRoutes:      []string{"192.168.1.0/24"},
			localRoutes:    []string{"10.0.0.0/8"},
			expectedVpn:    false,
			expectedPrefix: netip.Prefix{},
		},
		{
			name:           "Default route ignored",
			addr:           "192.168.1.1",
			vpnRoutes:      []string{"0.0.0.0/0", "192.168.1.0/24"},
			localRoutes:    []string{"10.0.0.0/8"},
			expectedVpn:    true,
			expectedPrefix: netip.MustParsePrefix("192.168.1.0/24"),
		},
		{
			name:           "Default route matches but ignored",
			addr:           "172.16.1.1",
			vpnRoutes:      []string{"0.0.0.0/0", "192.168.1.0/24"},
			localRoutes:    []string{"10.0.0.0/8"},
			expectedVpn:    false,
			expectedPrefix: netip.Prefix{},
		},
		{
			name:           "Longest prefix match local",
			addr:           "192.168.1.1",
			vpnRoutes:      []string{"192.168.0.0/16"},
			localRoutes:    []string{"192.168.1.0/24"},
			expectedVpn:    false,
			expectedPrefix: netip.MustParsePrefix("192.168.1.0/24"),
		},
		{
			name:           "Longest prefix match local multiple",
			addr:           "192.168.0.1",
			vpnRoutes:      []string{"192.168.0.0/16", "192.168.0.0/25", "192.168.0.0/27"},
			localRoutes:    []string{"192.168.0.0/24", "192.168.0.0/26", "192.168.0.0/28"},
			expectedVpn:    false,
			expectedPrefix: netip.MustParsePrefix("192.168.0.0/28"),
		},
		{
			name:           "Longest prefix match vpn",
			addr:           "192.168.1.1",
			vpnRoutes:      []string{"192.168.1.0/24"},
			localRoutes:    []string{"192.168.0.0/16"},
			expectedVpn:    true,
			expectedPrefix: netip.MustParsePrefix("192.168.1.0/24"),
		},
		{
			name:           "Longest prefix match vpn multiple",
			addr:           "192.168.0.1",
			vpnRoutes:      []string{"192.168.0.0/16", "192.168.0.0/25", "192.168.0.0/27"},
			localRoutes:    []string{"192.168.0.0/24", "192.168.0.0/26"},
			expectedVpn:    true,
			expectedPrefix: netip.MustParsePrefix("192.168.0.0/27"),
		},
		{
			name:           "Duplicate prefix in both",
			addr:           "192.168.1.1",
			vpnRoutes:      []string{"192.168.1.0/24"},
			localRoutes:    []string{"192.168.1.0/24"},
			expectedVpn:    false,
			expectedPrefix: netip.MustParsePrefix("192.168.1.0/24"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, err := netip.ParseAddr(tt.addr)
			if err != nil {
				t.Fatalf("Failed to parse address %s: %v", tt.addr, err)
			}

			var vpnRoutes, localRoutes []netip.Prefix
			for _, route := range tt.vpnRoutes {
				prefix, err := netip.ParsePrefix(route)
				if err != nil {
					t.Fatalf("Failed to parse VPN route %s: %v", route, err)
				}
				vpnRoutes = append(vpnRoutes, prefix)
			}

			for _, route := range tt.localRoutes {
				prefix, err := netip.ParsePrefix(route)
				if err != nil {
					t.Fatalf("Failed to parse local route %s: %v", route, err)
				}
				localRoutes = append(localRoutes, prefix)
			}

			isVpn, matchedPrefix := isVpnRoute(addr, vpnRoutes, localRoutes)
			assert.Equal(t, tt.expectedVpn, isVpn, "isVpnRoute should return expectedVpn value")
			assert.Equal(t, tt.expectedPrefix, matchedPrefix, "isVpnRoute should return expectedVpn prefix")
		})
	}
}

// setupInMemoryTracer sets up an in-memory tracer provider and returns the exporter for inspection.
func setupInMemoryTracer() (*tracetest.InMemoryExporter, func()) {
	exporter := tracetest.NewInMemoryExporter()
	tp := trace.NewTracerProvider(
		trace.WithSyncer(exporter),
	)
	otel.SetTracerProvider(tp)

	cleanup := func() {
		_ = tp.Shutdown(context.Background())
	}

	return exporter, cleanup
}

// hasAttributeName checks if a span contains a specific attribute name
func hasAttributeName(span tracetest.SpanStub, attrName string) bool {
	for _, a := range span.Attributes {
		if string(a.Key) == attrName {
			return true
		}
	}

	return false
}
