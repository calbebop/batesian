package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"sync/atomic"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	server := mcp.NewServer(&mcp.Implementation{Name: "key-alias-fixture", Version: "1"}, nil)
	var calls atomic.Int64
	mcp.AddTool(server, &mcp.Tool{Name: "sentinel"},
		func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, struct{}, error) {
			calls.Add(1)
			return &mcp.CallToolResult{}, struct{}{}, nil
		})
	mux := http.NewServeMux()
	mux.Handle("/mcp", mcp.NewStreamableHTTPHandler(
		func(*http.Request) *mcp.Server { return server },
		&mcp.StreamableHTTPOptions{JSONResponse: true},
	))
	mux.HandleFunc("/__calls", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, calls.Load())
	})
	log.Fatal(http.ListenAndServe("127.0.0.1:7821", mux))
}
