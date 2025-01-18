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
	"encoding/json"
	"fmt"
	"time"

	"github.com/CycloneDX/sbom-utility/schema"
)

const (
	// Matches component package URLs starting with 'pkg:maven/p2', containing complete group/artifact/version information,
	// and matching one of the p2 packaging types
	REGEX_P2_PURL = `^pkg:maven/p2\.[\w\._-]+/[\w\._-]+@[\w\._-]+\?(classifier=[\w%-\.]+&)?type=(eclipse-plugin|eclipse-feature|p2-installable-unit)$`

	ECLIPSE_LICENSE_CHECK_SERVICE_URL = "https://www.eclipse.org/projects/services/license_check.php"
)

type Dependencies struct {
	Dependencies []string `json:"dependencies"`
}

type LicenseData struct {
	Approved map[string]Component `json:"approved"`
}

type Component struct {
	License string `json:"license"`
}

type P2ComponentLicenseFinderData struct {
	LicenseFinderData
}

var P2ComponentLicenseFinder *P2ComponentLicenseFinderData = &P2ComponentLicenseFinderData{
	LicenseFinderData: LicenseFinderData{
		licenseCacheFileName: ".p2-license-cache.dat",
		purlRegexpString:     REGEX_P2_PURL,
	},
}

func (finder *P2ComponentLicenseFinderData) FindLicenses(cdxComponent schema.CDXComponent) ([]schema.CDXLicenseChoice, error) {
	startTime := time.Now()
	defer func() {
		elapsedTime := time.Since(startTime)
		getLogger().Tracef("FindLicenses() execution time: %s\n", elapsedTime)
	}()

	if licenseChoices, found := finder.retrieveFromLicenseCache(cdxComponent); found {
		return licenseChoices, nil
	}

	licenseData, err := getLicenseDataFromEclipseLicenseCheckService(cdxComponent)
	if err != nil {
		return nil, err
	}

	licenseChoices, err := extractLicenseFromEclipseLicenseData(licenseData)
	if err != nil {
		return nil, err
	}

	finder.storeInLicenseCache(cdxComponent, licenseChoices)

	return licenseChoices, nil
}

func getLicenseDataFromEclipseLicenseCheckService(cdxComponent schema.CDXComponent) (*LicenseData, error) {
	// Build dependencies JSON
	getLogger().Tracef("trying to fetch license data from Eclipse license check service %s", ECLIPSE_LICENSE_CHECK_SERVICE_URL)
	requestJson, err := buildRequestJson(cdxComponent)
	if err != nil {
		return nil, err
	}

	// Request license data from Eclipse license check service
	responseJson, err := performHttpPostFormRequest(ECLIPSE_LICENSE_CHECK_SERVICE_URL, "request", requestJson)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch license data from Eclipse license check service: %w", err)
	}

	// Parse license data JSON
	licenseData, err := parseLicenseDataJson(responseJson)
	if err != nil {
		return nil, fmt.Errorf("unable to parse license data obtained from Eclipse license check service: %w", err)
	}
	return &licenseData, nil
}

func buildRequestJson(cdxComponent schema.CDXComponent) ([]byte, error) {
	dependencies := Dependencies{
		Dependencies: []string{fmt.Sprintf("p2/orbit/%s/%s/%s", cdxComponent.Group, cdxComponent.Name, cdxComponent.Version)},
	}

	dependenciesJson, err := json.Marshal(dependencies)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal dependencies JSON: %w", err)
	}
	return dependenciesJson, nil
}

func parseLicenseDataJson(licenseDataJson []byte) (licenseData LicenseData, err error) {
	if err := json.Unmarshal(licenseDataJson, &licenseData); err != nil {
		return licenseData, fmt.Errorf("unable to unmarshal license data JSON: %w", err)
	}
	return
}

func extractLicenseFromEclipseLicenseData(licenseData *LicenseData) ([]schema.CDXLicenseChoice, error) {
	// Retrieve value of license attribute in license data of first (and only) approved component
	var licenseString string
	for _, component := range licenseData.Approved {
		licenseString = component.License
	}

	// Ignore proprietary licenses prefixed by LicenseRef- from license expressions if any
	licenseRefRegex, err := getRegexForLicenseRefExpression()
	if err != nil {
		getLogger().Error(fmt.Errorf("unable to invoke regex. %v", err))
		return nil, err
	}
	licenseString = licenseRefRegex.ReplaceAllString(licenseString, "")

	// Build license choices
	licenseChoices, err := licenseStringToLicenseChoices(licenseString)
	if err != nil {
		return nil, err
	}
	return licenseChoices, nil
}
