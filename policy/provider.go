/*
 Copyright 2024 The OSCAL Compass Authors
 SPDX-License-Identifier: Apache-2.0
*/

package policy

// Generator defines methods for a specialized plugin that transforms
// generic Policy into plugin-specific policy artifacts.
type Generator interface {
	Provider
	// Generate policy artifacts for a specific policy engine.
	Generate(Policy) error
}

// Aggregator define methods for a specialized plugin that transforms
// and aggregates policy results.
type Aggregator interface {
	Provider
	// GetResults from a specific policy engine and transform into
	// PVPResults.
	GetResults(Policy) (PVPResult, error)
}

// Provider defines common methods for a C2P plugin.
type Provider interface {
	// Configure send configuration options and selected values to the
	// plugin.
	Configure(map[string]string) error
}
