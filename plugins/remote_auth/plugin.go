package main

import (
	"github.com/solo-io/ext-auth-plugins/api"
	impl "github.com/tidepool-org/gloo-remote-auth-plugin/plugins/remote_auth/pkg"
)

func main() {}

// Compile-time assertion
var _ api.ExtAuthPlugin = new(impl.RemoteAuthPlugin)

// This is the exported symbol that Gloo will look for.
//noinspection GoUnusedGlobalVariable
var Plugin impl.RemoteAuthPlugin
