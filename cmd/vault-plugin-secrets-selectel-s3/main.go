package main

import (
	"os"

	hclog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/plugin"

	selectel "github.com/clique-it-tech/vault-plugin-secrets-selectel-s3/internal/selectel"
)

func main() {
	apiClientMeta := &api.PluginAPIClientMeta{}
	flags := apiClientMeta.FlagSet()
	if err := flags.Parse(os.Args[1:]); err != nil {
		logger().Error("failed to parse flags", "error", err)
		os.Exit(1)
	}

	tlsConfig := apiClientMeta.GetTLSConfig()
	tlsProviderFunc := api.VaultPluginTLSProvider(tlsConfig)

	if err := plugin.ServeMultiplex(&plugin.ServeOpts{
		BackendFactoryFunc: selectel.Factory,
		TLSProviderFunc:    tlsProviderFunc,
	}); err != nil {
		logger().Error("plugin shutting down", "error", err)
		os.Exit(1)
	}
}

func logger() hclog.Logger {
	return hclog.New(&hclog.LoggerOptions{})
}
