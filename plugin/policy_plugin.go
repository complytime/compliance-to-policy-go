/*
 Copyright 2024 The OSCAL Compass Authors
 SPDX-License-Identifier: Apache-2.0
*/

package plugin

import (
	"context"

	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	"google.golang.org/grpc/codes"

	"github.com/oscal-compass/compliance-to-policy-go/v2/api/proto"
	"github.com/oscal-compass/compliance-to-policy-go/v2/policy"
)

// Plugin must return an RPC server for this plugin type.
var (
	_ proto.AggregatorServer = (*aggregatorService)(nil)
	_ proto.GeneratorServer  = (*generatorService)(nil)
)

type aggregatorService struct {
	proto.UnimplementedAggregatorServer
	Impl policy.Aggregator
}

func FromAggregator(pe policy.Aggregator) proto.AggregatorServer {
	return &aggregatorService{
		Impl: pe,
	}
}

func (p *aggregatorService) Configure(ctx context.Context, request *proto.ConfigureRequest) (*emptypb.Empty, error) {
	if err := p.Impl.Configure(request.Settings); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return nil, nil
}

func (p *aggregatorService) GetResults(ctx context.Context, request *proto.PolicyRequest) (*proto.ResultsResponse, error) {
	result, err := p.Impl.GetResults(NewPolicyFromProto(request))
	if err != nil {
		return &proto.ResultsResponse{}, status.Error(codes.Internal, err.Error())
	}
	return &proto.ResultsResponse{Result: ResultsToProto(result)}, nil
}

type generatorService struct {
	proto.UnimplementedGeneratorServer
	Impl policy.Generator
}

func FromGenerator(pe policy.Generator) proto.GeneratorServer {
	return &generatorService{
		Impl: pe,
	}
}

func (p *generatorService) Configure(ctx context.Context, request *proto.ConfigureRequest) (*emptypb.Empty, error) {
	if err := p.Impl.Configure(request.Settings); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return nil, nil
}

func (p *generatorService) Generate(ctx context.Context, request *proto.PolicyRequest) (*emptypb.Empty, error) {
	if err := p.Impl.Generate(NewPolicyFromProto(request)); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return nil, nil
}
