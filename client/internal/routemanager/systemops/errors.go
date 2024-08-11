package systemops

import "errors"

var errRouteDefaultGatewayToLocalIP = errors.New("prefix overlap with default gateway and route to local ip")
