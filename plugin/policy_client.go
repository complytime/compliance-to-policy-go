/*
 Copyright 2024 The OSCAL Compass Authors
 SPDX-License-Identifier: Apache-2.0
*/

package plugin

import (
	"context"

	"github.com/oscal-compass/compliance-to-policy-go/v2/api/proto"
	"github.com/oscal-compass/compliance-to-policy-go/v2/policy"
)

// Client must return an implementation of the corresponding interface that communicates over an RPC client.
var (
	_ policy.Aggregator = (*aggregatorClient)(nil)
	_ policy.Generator  = (*generatorClient)(nil)
)

type aggregatorClient struct {
	client proto.AggregatorClient
}

func (pvp *aggregatorClient) Configure(configuration map[string]string) error {
	request := proto.ConfigureRequest{
		Settings: configuration,
	}
	_, err := pvp.client.Configure(context.Background(), &request)
	if err != nil {
		return err
	}
	return nil
}

func (pvp *aggregatorClient) GetResults(p policy.Policy) (policy.PVPResult, error) {
	request := PolicyToProto(p)
	resp, err := pvp.client.GetResults(context.Background(), request)
	if err != nil {
		return policy.PVPResult{}, err
	}
	pvpResult := NewResultFromProto(resp.Result)
	return pvpResult, nil
}

type generatorClient struct {
	client proto.GeneratorClient
}

func (pvp *generatorClient) Configure(configuration map[string]string) error {
	request := proto.ConfigureRequest{
		Settings: configuration,
	}
	_, err := pvp.client.Configure(context.Background(), &request)
	if err != nil {
		return err
	}
	return nil
}

func (pvp *generatorClient) Generate(p policy.Policy) error {
	request := PolicyToProto(p)
	_, err := pvp.client.Generate(context.Background(), request)
	if err != nil {
		return err
	}
	return nil
}
