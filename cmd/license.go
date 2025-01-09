// SPDX-License-Identifier: Apache-2.0
/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package cmd

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/CycloneDX/sbom-utility/common"
	"github.com/CycloneDX/sbom-utility/schema"
	"github.com/spf13/cobra"

)

const (
	SUBCOMMAND_LICENSE_LIST   = "list"
	SUBCOMMAND_LICENSE_POLICY = "policy"
)

var VALID_SUBCOMMANDS_LICENSE = []string{SUBCOMMAND_LICENSE_LIST, SUBCOMMAND_LICENSE_POLICY}

// License list default values
const (
	LICENSE_LIST_NOT_APPLICABLE = "N/A"
	LICENSE_NO_ASSERTION        = "NOASSERTION"
)

const (
	REGEX_LICENSE_EXPRESSION = `\s+(AND|OR|WITH)\s+`
)

// compiled regexp. to save time
var licenseExpressionRegexp *regexp.Regexp

// "getter" for compiled regex expression
func getRegexForLicenseExpression() (regex *regexp.Regexp, err error) {
	if licenseExpressionRegexp == nil {
		licenseExpressionRegexp, err = regexp.Compile(REGEX_LICENSE_EXPRESSION)
	}
	regex = licenseExpressionRegexp
	return
}

func NewCommandLicense() *cobra.Command {
	var command = new(cobra.Command)
	command.Use = "license"
	command.Short = "Process licenses found in the BOM input file"
	command.Long = "Process licenses found in the BOM input file"
	command.RunE = licenseCmdImpl
	command.ValidArgs = VALID_SUBCOMMANDS_LICENSE
	command.PreRunE = func(cmd *cobra.Command, args []string) (err error) {
		// the license command requires at least 1 valid subcommand (argument)
		getLogger().Tracef("args: %v\n", args)
		if len(args) == 0 {
			return getLogger().Errorf("Missing required argument(s).")
		} else if len(args) > 1 {
			return getLogger().Errorf("Too many arguments provided: %v", args)
		}
		// Make sure subcommand is known
		if !preRunTestForSubcommand(command, VALID_SUBCOMMANDS_LICENSE, args[0]) {
			return getLogger().Errorf("Subcommand provided is not valid: `%v`", args[0])
		}
		return
	}
	return command
}

func licenseCmdImpl(cmd *cobra.Command, args []string) error {
	getLogger().Enter(args)
	defer getLogger().Exit()
	return nil
}

//------------------------------------
// CDX License hashing functions
//------------------------------------

// Hash ALL licenses found in the SBOM document
// Note: CDX spec. allows for licenses to be declared in the following places:
// 1. (root).metadata.licenses[]
// 2. (root).metadata.component.licenses[] + all "nested" components
// 3. (root).components[](.license[]) (each component + all "nested" components)
// 4. (root).services[](.license[]) (each service + all "nested" services)
func loadDocumentLicenses(bom *schema.BOM, policyConfig *schema.LicensePolicyConfig, whereFilters []common.WhereFilter) (err error) {
	getLogger().Enter()
	defer getLogger().Exit(err)

	// NOTE: DEBUG: use this to debug license policy hashmaps have appropriate # of entries
	//licensePolicyConfig.Debug()

	// At this time, fail SPDX format SBOMs as "unsupported" (for "any" format)
	if !bom.FormatInfo.IsCycloneDx() {
		err = schema.NewUnsupportedFormatForCommandError(
			bom.GetFilename(),
			bom.FormatInfo.CanonicalName,
			CMD_LICENSE, FORMAT_ANY)
		return
	}

	// Before looking for license data, fully unmarshal the SBOM
	// into named structures
	if err = bom.UnmarshalCycloneDXBOM(); err != nil {
		return
	}

	// 1. Hash all licenses in the SBOM metadata (i.e., (root).metadata.component)
	// Note: this SHOULD represent a summary of all licenses that apply
	// to the component being described in the SBOM
	if err = hashMetadataLicenses(bom, policyConfig, schema.LC_LOC_METADATA, whereFilters); err != nil {
		return
	}

	// 2. Hash all licenses in (root).metadata.component (+ "nested" components)
	if err = hashMetadataComponentLicenses(bom, policyConfig, schema.LC_LOC_METADATA_COMPONENT, whereFilters); err != nil {
		return
	}

	// 3. Hash all component licenses found in the (root).components[] (+ "nested" components)
	pComponents := bom.GetCdxComponents()
	if pComponents != nil && len(*pComponents) > 0 {
		if err = hashComponentsLicenses(bom, policyConfig, *pComponents, schema.LC_LOC_COMPONENTS, whereFilters); err != nil {
			return
		}
	}

	// 4. Hash all service licenses found in the (root).services[] (array) (+ "nested" services)
	pServices := bom.GetCdxServices()
	if pServices != nil && len(*pServices) > 0 {
		if err = hashServicesLicenses(bom, policyConfig, *pServices, schema.LC_LOC_SERVICES, whereFilters); err != nil {
			return
		}
	}

	return
}

// Hash the license found in the (root).metadata.licenses[] array
func hashMetadataLicenses(bom *schema.BOM, policyConfig *schema.LicensePolicyConfig, location int, whereFilters []common.WhereFilter) (err error) {
	getLogger().Enter()
	defer getLogger().Exit(err)

	pLicenses := bom.GetCdxMetadataLicenses()
	if pLicenses == nil {
		sbomError := NewInvalidSBOMError(
			bom,
			fmt.Sprintf("%s (%s)",
				MSG_LICENSES_NOT_FOUND,
				schema.GetLicenseChoiceLocationName(location)),
			nil, nil)
		// Issue a warning as an SBOM without at least one, top-level license
		// (in the metadata license summary) SHOULD be noted.
		// Note: An actual error SHOULD ONLY be returned by
		// the custom validation code.
		getLogger().Warning(sbomError)
		return
	}

	var licenseInfo schema.LicenseInfo
	for _, pLicenseChoice := range *pLicenses {
		getLogger().Tracef("hashing license: id: `%s`, name: `%s`",
			pLicenseChoice.License.Id, pLicenseChoice.License.Name)

		licenseInfo.LicenseChoice = pLicenseChoice
		licenseInfo.BOMLocationValue = location
		licenseInfo.ResourceName = LICENSE_LIST_NOT_APPLICABLE
		licenseInfo.BOMRef = LICENSE_LIST_NOT_APPLICABLE
		err = hashLicenseInfoByLicenseType(bom, policyConfig, licenseInfo, whereFilters)
		if err != nil {
			return
		}
	}

	return
}

// Hash the license found in the (root).metadata.component object (and any "nested" components)
func hashMetadataComponentLicenses(bom *schema.BOM, policyConfig *schema.LicensePolicyConfig, location int, whereFilters []common.WhereFilter) (err error) {
	getLogger().Enter()
	defer getLogger().Exit(err)

	component := bom.GetCdxMetadataComponent()
	if component == nil {
		sbomError := NewInvalidSBOMError(
			bom,
			fmt.Sprintf("%s (%s)",
				MSG_LICENSES_NOT_FOUND,
				schema.GetLicenseChoiceLocationName(location)),
			nil, nil)
		// Issue a warning as an SBOM without at least one
		// top-level component license declared SHOULD be noted.
		// Note: An actual error SHOULD ONLY be returned by
		// the custom validation code.
		getLogger().Warning(sbomError)
		return
	}

	_, err = hashComponentLicense(bom, policyConfig, *component, location, whereFilters)

	return
}

// Hash all licenses found in an array of CDX Components
// TODO use array of pointer to []CDXComponent
func hashComponentsLicenses(bom *schema.BOM, policyConfig *schema.LicensePolicyConfig, components []schema.CDXComponent, location int, whereFilters []common.WhereFilter) (err error) {
	getLogger().Enter()
	defer getLogger().Exit(err)

	for _, cdxComponent := range components {
		_, err = hashComponentLicense(bom, policyConfig, cdxComponent, location, whereFilters)
		if err != nil {
			return
		}
	}
	return
}

// Hash all licenses found in an array of CDX Services
// TODO use array of pointer to []CDXService
func hashServicesLicenses(bom *schema.BOM, policyConfig *schema.LicensePolicyConfig, services []schema.CDXService, location int, whereFilters []common.WhereFilter) (err error) {
	getLogger().Enter()
	defer getLogger().Exit(err)

	for _, cdxServices := range services {
		err = hashServiceLicense(bom, policyConfig, cdxServices, location, whereFilters)
		if err != nil {
			return
		}
	}
	return
}

// Hash a CDX Component's licenses and recursively those of any "nested" components
func hashComponentLicense(bom *schema.BOM, policyConfig *schema.LicensePolicyConfig, cdxComponent schema.CDXComponent, location int, whereFilters []common.WhereFilter) (li *schema.LicenseInfo, err error) {
	getLogger().Enter()
	defer getLogger().Exit(err)
	var licenseInfo schema.LicenseInfo

	// Extract group from name if the latter appears to be a composed name
	// (e.g. "name": "org.apache.commons/commons-lang3" -> "group": "org.apache.commons", "name": "commons-lang3")
	if cdxComponent.Group == "" && strings.Contains(cdxComponent.Name, "/") {
		compositeName := strings.Split(cdxComponent.Name, "/")
		if len(compositeName) == 2 {
			cdxComponent.Group = compositeName[0]
			cdxComponent.Name = compositeName[1]
		}
	}

	pLicenses := cdxComponent.Licenses
	if pLicenses == nil || len(*pLicenses) == 0 {
		wellknownLicenseChoiceTypeValue, wellknownLicenseCharacteristic := LookupLicenseForWellknownComponents(cdxComponent)
		if wellknownLicenseChoiceTypeValue != schema.LC_TYPE_INVALID {
			var licenseChoices []schema.CDXLicenseChoice
			switch wellknownLicenseChoiceTypeValue {
			case schema.LC_TYPE_ID:
				licenseChoices = append(licenseChoices, schema.CDXLicenseChoice{
					License: &schema.CDXLicense{
						Id: wellknownLicenseCharacteristic,
					},
				})
			case schema.LC_TYPE_NAME:
				licenseChoices = append(licenseChoices, schema.CDXLicenseChoice{
					License: &schema.CDXLicense{
						Name: wellknownLicenseCharacteristic,
					},
				})
			case schema.LC_TYPE_EXPRESSION:
				licenseChoices = append(licenseChoices, schema.CDXLicenseChoice{
					CDXLicenseExpression: schema.CDXLicenseExpression{
						Expression: wellknownLicenseCharacteristic,
					},
				})
			}
			pLicenses = &licenseChoices
		}
	}

	if pLicenses == nil || len(*pLicenses) == 0 {
		// Fully qualified Maven component?
		var yes bool
		yes, err = IsFullyQualifiedMavenComponent(cdxComponent)
		if err != nil {
			return
		}
		if yes {
			getLogger().Infof("Trying to find license for %s:%s:%s on Maven Central\n", cdxComponent.Group, cdxComponent.Name, cdxComponent.Version)
			pomLicenses, e := FindLicensesInPom(cdxComponent)
			if e == nil && len(pomLicenses) > 0 {
				var licenseChoices []schema.CDXLicenseChoice
				for i := 0; i < len(pomLicenses); i += 2 {
					licenseChoices = append(licenseChoices, schema.CDXLicenseChoice{
						License: &schema.CDXLicense{
							Name: pomLicenses[i],
							Url:  pomLicenses[i+1],
						},
					})
				}
				pLicenses = &licenseChoices
			} else {
				getLogger().Warningf("Unable to detect licenses for: %s", cdxComponent.Purl)
			}
		}

		// Fully qualified p2 component?
		yes, err = IsFullyQualifiedP2Component(cdxComponent)
		if err != nil {
			return
		}
		if yes {
			getLogger().Infof("Trying to find license for %s:%s:%s through Eclipse license check service\n", cdxComponent.Group, cdxComponent.Name, cdxComponent.Version)
			eclipseLicense, e := QueryEclipseLicenseCheckService(cdxComponent)
			if e == nil && len(eclipseLicense) > 0 {
				regex, e := getRegexForLicenseExpression()
				if e != nil {
					getLogger().Error(fmt.Errorf("unable to invoke regex. %v", e))
					err = e
					return
				}

				result := regex.MatchString(eclipseLicense)
				if result {
					licenseChoices := []schema.CDXLicenseChoice{
						{
							CDXLicenseExpression: schema.CDXLicenseExpression{
								Expression: eclipseLicense,
							},
						},
					}
					pLicenses = &licenseChoices
				} else {
					licenseChoices := []schema.CDXLicenseChoice{
						{
							License: &schema.CDXLicense{
								Id: eclipseLicense,
							},
						},
					}
					pLicenses = &licenseChoices
				}
			} else {
				getLogger().Warningf("Unable to detect licenses for: %s", cdxComponent.Purl)
			}
		}
	}

	if pLicenses != nil && len(*pLicenses) > 0 {
		if (len(*pLicenses) > 1) {
			// Convert multiple licenses into a single license expression using the OR operator
			// (see https://maven.apache.org/ref/3-LATEST/maven-model/maven.html > licenses/license for justification)
			var licenseExpressionParts []string
			for _, licenseChoice := range *pLicenses {
				if licenseChoice.License != nil {
					if licenseChoice.License.Id != "" {
						licenseExpressionParts = append(licenseExpressionParts, licenseChoice.License.Id)
					} else if licenseChoice.License.Url != "" {
						licenseExpressionParts = append(licenseExpressionParts, licenseChoice.License.Url)
					} else if licenseChoice.License.Name != "" {
						licenseExpressionParts = append(licenseExpressionParts, licenseChoice.License.Name)
					} else {
						getLogger().Errorf("Unable to include license w/o license id and URL in license expression for component with multiple licenses: %v", licenseInfo)
					}
				} else if licenseChoice.CDXLicenseExpression.Expression != "" {
					licenseExpressionParts = append(licenseExpressionParts, schema.LEFT_PARENS + " " + licenseChoice.CDXLicenseExpression.Expression + " " + schema.RIGHT_PARENS)
				} else {
					getLogger().Errorf("Unable to include empty license in license expression for component with multiple licenses: %v", licenseInfo)
				}
			}
			licenseInfo.LicenseChoice = schema.CDXLicenseChoice{
				CDXLicenseExpression: schema.CDXLicenseExpression{
					Expression: strings.Join(licenseExpressionParts, " " + schema.OR + " "),
				},
			}
		} else {
			licenseInfo.LicenseChoice = (*pLicenses)[0]
		}

		getLogger().Debugf("licenseChoice: %s", getLogger().FormatStruct(licenseInfo.LicenseChoice))
		getLogger().Tracef("hashing license for component=`%s`", cdxComponent.Name)

		licenseInfo.Component = cdxComponent
		licenseInfo.BOMLocationValue = location
		licenseInfo.ResourceName = cdxComponent.Name
		if cdxComponent.BOMRef != nil {
			licenseInfo.BOMRef = *cdxComponent.BOMRef
		}

		err = hashLicenseInfoByLicenseType(bom, policyConfig, licenseInfo, whereFilters)
		if err != nil {
			// Show intent to not check for error returns as there no intent to recover
			getLogger().Errorf("Unable to hash empty license: %v", licenseInfo)
			return
		}
	} else {
		// Account for component with no license with an "UNDEFINED" entry
		// hash any component w/o a license using special key name
		licenseInfo.Component = cdxComponent
		licenseInfo.BOMLocationValue = location
		licenseInfo.ResourceName = cdxComponent.Name
		if cdxComponent.BOMRef != nil {
			licenseInfo.BOMRef = *cdxComponent.BOMRef
		}

		_, err = bom.HashLicenseInfo(policyConfig, LICENSE_NO_ASSERTION, licenseInfo, whereFilters)

		getLogger().Warningf("%s: %s (name:`%s`, version: `%s`, package-url: `%s`)",
			"No license found for component. bomRef",
			licenseInfo.BOMRef,
			licenseInfo.ResourceName,
			cdxComponent.Version,
			cdxComponent.Purl)
		// No actual licenses to process
		return
	}

	// Recursively hash licenses for all child components (i.e., hierarchical composition)
	pComponents := cdxComponent.Components
	if pComponents != nil && len(*pComponents) > 0 {
		err = hashComponentsLicenses(bom, policyConfig, *pComponents, location, whereFilters)
		if err != nil {
			return
		}
	}

	return
}

// Hash all licenses found in a CDX Service
// TODO use pointer to CDXService
func hashServiceLicense(bom *schema.BOM, policyConfig *schema.LicensePolicyConfig, cdxService schema.CDXService, location int, whereFilters []common.WhereFilter) (err error) {
	getLogger().Enter()
	defer getLogger().Exit(err)

	var licenseInfo schema.LicenseInfo

	pLicenses := cdxService.Licenses
	if pLicenses != nil && len(*pLicenses) > 0 {
		for _, licenseChoice := range *pLicenses {
			getLogger().Debugf("licenseChoice: %s", getLogger().FormatStruct(licenseChoice))
			getLogger().Tracef("Hashing license for service=`%s`", cdxService.Name)
			licenseInfo.LicenseChoice = licenseChoice
			licenseInfo.Service = cdxService
			licenseInfo.ResourceName = cdxService.Name
			if cdxService.BOMRef != nil {
				licenseInfo.BOMRef = *cdxService.BOMRef
			}
			licenseInfo.BOMLocationValue = location
			err = hashLicenseInfoByLicenseType(bom, policyConfig, licenseInfo, whereFilters)

			if err != nil {
				return
			}
		}
	} else {
		// Account for service with no license with an "UNDEFINED" entry
		// hash any service w/o a license using special key name
		licenseInfo.Service = cdxService
		licenseInfo.BOMLocationValue = location
		licenseInfo.ResourceName = cdxService.Name
		if cdxService.BOMRef != nil {
			licenseInfo.BOMRef = *cdxService.BOMRef
		}
		_, err = bom.HashLicenseInfo(policyConfig, LICENSE_NO_ASSERTION, licenseInfo, whereFilters)

		getLogger().Warningf("%s: %s (name: `%s`, version: `%s`)",
			"No license found for service. bomRef",
			cdxService.BOMRef,
			cdxService.Name,
			cdxService.Version)

		// No actual licenses to process
		return
	}

	// Recursively hash licenses for all child components (i.e., hierarchical composition)
	pServices := cdxService.Services
	if pServices != nil && len(*pServices) > 0 {
		err = hashServicesLicenses(bom, policyConfig, *pServices, location, whereFilters)
		if err != nil {
			// Show intent to not check for error returns as there is no recovery
			_ = getLogger().Errorf("Unable to hash empty license: %v", licenseInfo)
			return
		}
	}

	return
}

// Wrap the license data itself in a "licenseInfo" object which tracks:
// 1. What type of information do we have about the license (i.e., SPDX ID, Name or expression)
// 2. Where the license was found within the SBOM
// 3. The entity name (e.g., service or component name) that declared the license
// 4. The entity local BOM reference (i.e., "bomRef")
func hashLicenseInfoByLicenseType(bom *schema.BOM, policyConfig *schema.LicensePolicyConfig, licenseInfo schema.LicenseInfo, whereFilters []common.WhereFilter) (err error) {
	getLogger().Enter()
	defer getLogger().Exit(err)

	defer func() {
		if err != nil {
			baseError := NewSbomLicenseDataError()
			baseError.AppendMessage(fmt.Sprintf(": for entity: `%s` (%s)",
				licenseInfo.BOMRef,
				licenseInfo.ResourceName))
			err = baseError
		}
	}()

	var licenseInfoKey string
	pLicense := licenseInfo.LicenseChoice.License

	if pLicense != nil {
		if pLicense.Id != "" {
			licenseInfo.LicenseChoiceTypeValue = schema.LC_TYPE_ID
			_, err = bom.HashLicenseInfo(policyConfig, pLicense.Id, licenseInfo, whereFilters)
			return
		}

		// Fix up licenses with sloppy/really weird names
		if pLicense.Name != "" {
			licenseInfoKey = pLicense.Name
			// License name actually being a single or multiple license URLs?
			if schema.IsUrlish(pLicense.Name) {
				var licenseUrls []string
				licenseUrls, err = schema.SplitUrls(pLicense.Name)
				if err != nil {
					return
				}
				if len(licenseUrls) == 1 {
					// Move license URL to appropriate field
					pLicense.Url = licenseUrls[0]
				} else {
					// Flip license into license expression using OR operator and license URLs instead of license ids
					for i, url := range licenseUrls {
						if i == 0 {
							licenseInfo.LicenseChoice.Expression = url
						} else {
							licenseInfo.LicenseChoice.Expression += " " + schema.OR + " " + url
						}
					}
				}
				pLicense.Name = ""
			}

			// License name actually being a license expression?
			if schema.HasLogicalConjunctionOrPreposition(pLicense.Name) {
				// Flip license into license expression
				licenseInfo.LicenseChoice.Expression = pLicense.Name
				pLicense.Name = ""
			}
		} else {
			licenseInfoKey = pLicense.Url
		}

		if pLicense.Name != "" {
			licenseInfo.LicenseChoiceTypeValue = schema.LC_TYPE_NAME
			_, err = bom.HashLicenseInfo(policyConfig, licenseInfoKey, licenseInfo, whereFilters)
			return
		}
		if pLicense.Url != "" {
			licenseInfo.LicenseChoiceTypeValue = schema.LC_TYPE_NAME
			_, err = bom.HashLicenseInfo(policyConfig, licenseInfoKey, licenseInfo, whereFilters)
			return
		}
	} else {
		licenseInfoKey = licenseInfo.LicenseChoice.Expression
	}

	if licenseInfo.LicenseChoice.Expression != "" {
		licenseInfo.LicenseChoiceTypeValue = schema.LC_TYPE_EXPRESSION
		_, err = bom.HashLicenseInfo(policyConfig, licenseInfoKey, licenseInfo, whereFilters)
		return
	}

	// Note: This code path only executes if hashing is performed
	// without schema validation (which would find this as an error)
	// Note: licenseInfo.LicenseChoiceType = 0 // default, invalid
	baseError := NewSbomLicenseDataError()
	baseError.AppendMessage(fmt.Sprintf(": for entity: `%s` (%s)",
		licenseInfo.BOMRef,
		licenseInfo.ResourceName))
	err = baseError
	return
}
