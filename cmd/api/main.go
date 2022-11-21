// Package main is the entry point to start the cerebrum server
package main

import (
	"bni/dgb/digi46/labs/auth-service-digi46/application/pkg/api"
	"bni/dgb/digi46/labs/auth-service-digi46/application/pkg/utl/config"
	"bni/dgb/digi46/labs/auth-service-digi46/application/pkg/utl/support"
)

// main server
func main() {
	cfgPath, err := support.ExtractPathFromFlags()
	if err != nil {
		panic(err.Error())
	}

	cfg, err := config.LoadConfigFrom(cfgPath)
	if err != nil {
		panic(err.Error())
	}
	
	if cfg == nil {
		panic("unknown error loading yaml file")
	}

	if err = api.Start(cfg); err != nil {
		panic(err.Error())
	}
}