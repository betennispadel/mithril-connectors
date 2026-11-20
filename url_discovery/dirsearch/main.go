package main

import (
	"context"
	"log"

	sdkconn "github.com/betennispadel/mithril-connectors/sdk/connector"
	"github.com/betennispadel/mithril-connectors/sdk/runtime"
)

func main() {
	adapter := DirsearchAdapter{}
	conn := sdkconn.New(adapter)
	rt := runtime.New(conn)
	if err := rt.Run(context.Background()); err != nil {
		log.Fatalf("dirsearch connector: %v", err)
	}
}
