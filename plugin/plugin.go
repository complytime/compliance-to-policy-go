/*
 Copyright 2024 The OSCAL Compass Authors
 SPDX-License-Identifier: Apache-2.0
*/

package plugin

import (
	"context"

	"github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"

	"github.com/oscal-compass/compliance-to-policy-go/v2/api/proto"
	"github.com/oscal-compass/compliance-to-policy-go/v2/policy"
)

const (
	// AggregationPluginName is used to dispense an AggregatorPlugin type
	AggregationPluginName = "aggregation"
	// GenerationPluginName is used to dispense a GeneratorPlugin type
	GenerationPluginName = "generation"
	// The ProtocolVersion is the version that must match between the core
	// and plugins.
	ProtocolVersion = 1
)

// Validate ensures the plugin id is valid based on the
// plugin IdentifierPattern.
func (i ID) Validate() bool {
	return IdentifierPattern.MatchString(i.String())
}

// Handshake is a common handshake that is shared by plugin and host.
var Handshake = plugin.HandshakeConfig{
	ProtocolVersion: ProtocolVersion,

	// These magic cookie values should only be set one time.
	// Please do NOT change.
	MagicCookieKey:   "C2P_PLUGIN_MAGIC_COOKIE",
	MagicCookieValue: "4fc73041107cf346f76f14d178c3ce63ebb7f6d09d7e2e3983a5737e149e3bfb",
}

// SupportedPlugins is the map of plugins we can dispense.
var SupportedPlugins = map[string]plugin.Plugin{
	AggregationPluginName: &AggregatorPlugin{},
	GenerationPluginName:  &GeneratorPlugin{},
}

var _ plugin.GRPCPlugin = (*AggregatorPlugin)(nil)
var _ plugin.GRPCPlugin = (*GeneratorPlugin)(nil)

// AggregatorPlugin is concrete implementation of the policy.Aggregator written in Go for use
// with go-plugin.
type AggregatorPlugin struct {
	plugin.Plugin
	Impl policy.Aggregator
}

func (p *AggregatorPlugin) GRPCServer(broker *plugin.GRPCBroker, s *grpc.Server) error {
	proto.RegisterAggregatorServer(s, FromAggregator(p.Impl))
	return nil
}

func (p *AggregatorPlugin) GRPCClient(ctx context.Context, broker *plugin.GRPCBroker, c *grpc.ClientConn) (interface{}, error) {
	return &aggregatorClient{client: proto.NewAggregatorClient(c)}, nil
}

// GeneratorPlugin is concrete implementation of the policy.Generator written in Go for use
// with go-plugin.
type GeneratorPlugin struct {
	plugin.Plugin
	Impl policy.Generator
}

func (p *GeneratorPlugin) GRPCServer(broker *plugin.GRPCBroker, s *grpc.Server) error {
	proto.RegisterGeneratorServer(s, FromGenerator(p.Impl))
	return nil
}

func (p *GeneratorPlugin) GRPCClient(ctx context.Context, broker *plugin.GRPCBroker, c *grpc.ClientConn) (interface{}, error) {
	return &generatorClient{client: proto.NewGeneratorClient(c)}, nil
}
