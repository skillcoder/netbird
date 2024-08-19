//go:build !android && !ios

package systemops

// Expose private function for tests
var ExistsInRouteTable = existsInRouteTable
