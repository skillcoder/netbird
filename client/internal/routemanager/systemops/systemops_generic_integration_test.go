//go:build integration && !android && !ios

package systemops_test

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"testing"

	"github.com/pion/transport/v3/stdnet"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/internal/routemanager/systemops"
	"github.com/netbirdio/netbird/iface"
)

// NOTE(dirty): this test change machine state and keep it dirty, MUST run only in docker or with VM
func TestShouldAlsoAddDefaultGatewayRoute(t *testing.T) {
	defaultNexthop, err := systemops.GetNextHop(netip.MustParseAddr("0.0.0.0"))
	t.Log("defaultNexthop: ", defaultNexthop)
	if err != nil {
		t.Fatal("shouldn't return error when fetching the gateway: ", err)
	}

	testCases := []struct {
		name           string
		prefix         netip.Prefix
		notExistPrefix netip.Prefix
	}{
		{
			name:           "Should Add route And Default Gateway route if overlaps with default gateway",
			prefix:         netip.MustParsePrefix(defaultNexthop.IP.String() + "/31"),
			notExistPrefix: netip.MustParsePrefix(defaultNexthop.IP.String() + "/32"),
		},
	}

	for n, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Setenv("NB_USE_LEGACY_ROUTING", "true")
			t.Setenv("NB_DISABLE_ROUTE_CACHE", "true")

			ctx := context.Background()

			peerPrivateKey, _ := wgtypes.GeneratePrivateKey()
			newNet, err := stdnet.NewNet()
			if err != nil {
				t.Fatal(err)
			}

			wgInterface, err := iface.NewWGIFace(fmt.Sprintf("utun55%d", n), "100.65.75.2/24", 33105, peerPrivateKey.String(), iface.DefaultMTU, newNet, nil, nil)
			require.NoError(t, err, "should create testing WGIface interface")
			defer wgInterface.Close()

			err = wgInterface.Create()
			require.NoError(t, err, "should create testing wireguard interface")

			index, err := net.InterfaceByName(wgInterface.Name())
			require.NoError(t, err, "InterfaceByName should not return err")
			intf := &net.Interface{Index: index.Index, Name: wgInterface.Name()}

			r := systemops.NewSysOps(wgInterface, nil)

			// Check testing environment
			// Every routes we using in this our tests should not exist
			ok, err := systemops.ExistsInRouteTable(testCase.prefix)
			require.NoError(t, err, "should not return err")
			require.False(t, ok, "testing route should not exist before the test: %s", testCase.prefix)

			// Prepare the environment
			if testCase.notExistPrefix.IsValid() {
				ok, err := systemops.ExistsInRouteTable(testCase.notExistPrefix)
				require.NoError(t, err, "should not return err")

				if ok {
					// NOTE(dirty): here we heavily change os state
					err = r.RemoveVPNRoute(ctx, testCase.notExistPrefix, intf)
					require.NoError(t, err, "should not return err when remove prefix which should not exist")
				}
			}

			// Add the route
			err = r.AddVPNRoute(ctx, testCase.prefix, intf)
			require.NoError(t, err, "should not return err when adding route")

			ok, err = systemops.ExistsInRouteTable(testCase.prefix)
			require.NoError(t, err, "should not return err")
			require.True(t, ok, "route should not exist: %s", testCase.prefix)

			ok, err = systemops.ExistsInRouteTable(testCase.notExistPrefix)
			require.NoError(t, err, "should not return err")
			require.True(t, ok, "route should not exist: %s", testCase.prefix)

			// cleanup
			err = r.RemoveVPNRoute(ctx, testCase.prefix, intf)
			require.NoError(t, err, "should not return err")

			// route should either not have been added or should have been removed
			// In case of already existing route, it should not have been added (but still exist)
			ok, err = systemops.ExistsInRouteTable(testCase.prefix)
			require.NoError(t, err, "should not return err")
			require.False(t, ok, "route should not exist: %s", testCase.prefix)
		})
	}
}
