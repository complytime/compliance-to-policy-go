/*
 Copyright 2025 The OSCAL Compass Authors
 SPDX-License-Identifier: Apache-2.0
*/

package subcommands

import (
	"errors"
	"os"

	oscalTypes "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-2"
	"github.com/oscal-compass/oscal-sdk-go/models"
	"github.com/oscal-compass/oscal-sdk-go/models/components"
	"github.com/oscal-compass/oscal-sdk-go/settings"
	"github.com/oscal-compass/oscal-sdk-go/validation"

	"github.com/oscal-compass/compliance-to-policy-go/v2/framework"
	"github.com/oscal-compass/compliance-to-policy-go/v2/framework/action"
)

// Config returns a populated C2PConfig for the CLI to use.
func Config(option *Options) (*framework.C2PConfig, error) {
	c2pConfig := framework.DefaultConfig()
	pluginsPath := option.PluginDir
	if pluginsPath != "" {
		c2pConfig.PluginDir = pluginsPath
	}
	// Set logger
	c2pConfig.Logger = option.logger
	return c2pConfig, nil
}

func Context(compDef oscalTypes.ComponentDefinition) (*action.InputContext, error) {
	if compDef.Components == nil {
		return nil, errors.New("component definition components cannot be nil")
	}

	var allComponents []components.Component
	for _, component := range *compDef.Components {
		compAdapter := components.NewDefinedComponentAdapter(component)
		allComponents = append(allComponents, compAdapter)
	}
	return action.NewContext(allComponents)
}

func loadCompDef(path string) (oscalTypes.ComponentDefinition, error) {
	file, err := os.Open(path)
	if err != nil {
		return oscalTypes.ComponentDefinition{}, err
	}
	defer file.Close()
	compDef, err := models.NewComponentDefinition(file, validation.NewSchemaValidator())
	if err != nil {
		return oscalTypes.ComponentDefinition{}, err
	}

	if compDef == nil {
		return oscalTypes.ComponentDefinition{}, errors.New("component definition cannot be nil")
	}
	return *compDef, nil
}

// Settings returns extracted compliance settings from a given component definition implementation using the C2PConfig.
func Settings(option *Options, compDef oscalTypes.ComponentDefinition) (*settings.ImplementationSettings, error) {
	if compDef.Components == nil {
		return nil, errors.New("component definition components cannot be nil")
	}
	var implementation []oscalTypes.ControlImplementationSet
	for _, cp := range *compDef.Components {
		if cp.ControlImplementations != nil {
			implementation = append(implementation, *cp.ControlImplementations...)
		}
	}
	return settings.Framework(option.Name, implementation)
}
