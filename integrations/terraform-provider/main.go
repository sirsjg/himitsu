// Command terraform-provider-himitsu serves the Himitsu Terraform provider.
package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"

	"github.com/sirsjg/himitsu-enterprise/integrations/terraform-provider/internal/provider"
)

// version is overwritten at release time with -ldflags="-X main.version=…".
var version = "dev"

func main() {
	var debug bool
	flag.BoolVar(&debug, "debug", false, "Run with support for debuggers like delve.")
	flag.Parse()

	err := providerserver.Serve(context.Background(), provider.New(version), providerserver.ServeOpts{
		Address: "registry.terraform.io/sirsjg/himitsu",
		Debug:   debug,
	})
	if err != nil {
		log.Fatal(err.Error())
	}
}
