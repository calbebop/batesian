//go:build ignore

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
)

func main() {
	card := map[string]interface{}{
		"name":        "Demo Research Agent",
		"description": "A demonstration A2A agent for research and summarization tasks",
		"version":     "1.2.0",
		"supportedInterfaces": []map[string]string{
			{"url": "http://localhost:7777", "protocolBinding": "HTTP+JSON", "protocolVersion": "1.0"},
		},
		"provider": map[string]string{
			"organization": "Demo Corp",
			"url":          "https://demo.example.com",
		},
		"capabilities": map[string]interface{}{
			"streaming":         true,
			"pushNotifications": true,
			"extendedAgentCard": true,
		},
		"securitySchemes": map[string]interface{}{
			"bearerAuth": map[string]interface{}{
				"httpAuthSecurityScheme": map[string]string{
					"scheme":       "Bearer",
					"bearerFormat": "JWT",
				},
			},
		},
		"securityRequirements": []map[string][]string{{"bearerAuth": {}}},
		"defaultInputModes":    []string{"text/plain", "application/json"},
		"defaultOutputModes":   []string{"application/json"},
		"skills": []map[string]interface{}{
			{
				"id":          "summarize",
				"name":        "Document Summarizer",
				"description": "Summarizes documents using LLMs",
				"tags":        []string{"nlp", "summarization"},
			},
			{
				"id":          "fact-check",
				"name":        "Fact Checker",
				"description": "Verifies factual claims against sources",
				"tags":        []string{"nlp", "verification", "research"},
			},
		},
	}

	http.HandleFunc("/.well-known/agent-card.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(card) //nolint:errcheck
	})

	// /extendedAgentCard intentionally returns 200 without auth to simulate a2a-extcard-unauth-001
	http.HandleFunc("/extendedAgentCard", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"internal": "top-secret-tool-config"}) //nolint:errcheck
	})

	fmt.Println("mock A2A server on :7777")
	http.ListenAndServe(":7777", nil) //nolint:errcheck
}
