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
	"net/url"
	"time"

	"github.com/CycloneDX/sbom-utility/schema"

)

const (
	// Matches component package URLs starting with 'pkg:npm' and containing complete group/artifact/version information
	REGEX_NPM_PURL = `^pkg:npm/@?[\w\._-]+/[\w\._-]+@[\w\._-]+$`

	NPM_BASE_URL = "https://registry.npmjs.org"
)

type PackageInfo struct {
	License string `json:"license"`
}

type NpmComponentLicenseFinderData struct {
	LicenseFinderData
}

var NpmComponentLicenseFinder *NpmComponentLicenseFinderData = &NpmComponentLicenseFinderData{
	LicenseFinderData: LicenseFinderData{
		licenseCacheFileName: ".npm-license-cache.dat",
		purlRegexpString:     REGEX_NPM_PURL,
	},
}

func (finder *NpmComponentLicenseFinderData) FindLicenses(cdxComponent schema.CDXComponent) ([]schema.CDXLicenseChoice, error) {
	startTime := time.Now()
	defer func() {
		elapsedTime := time.Since(startTime)
		getLogger().Tracef("FindLicenses() execution time: %s\n", elapsedTime)
	}()

	if licenseChoices, found := finder.retrieveFromLicenseCache(cdxComponent); found {
		return licenseChoices, nil
	}

	packageInfo, err := getPackageInfoFromNpmRegistry(cdxComponent)
	if err != nil {
		return nil, err
	}

	licenseChoices, err := extractLicenseFromNpmPackageInfo(packageInfo)
	if err != nil {
		return nil, err
	}

	finder.storeInLicenseCache(cdxComponent, licenseChoices)

	return licenseChoices, nil
}

func getPackageInfoFromNpmRegistry(cdxComponent schema.CDXComponent) (*PackageInfo, error) {
	// Compose npm registry URL to be reached out to
	requestURL, err := formatNpmPackageInfoURL(cdxComponent)
	if err != nil {
		return nil, err
	}
	getLogger().Tracef("trying to fetch package info from npm registry %s", requestURL)

	// Get package info from npm registry
	responseJson, err := performHttpGetRequest(requestURL)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch package info from npm registry: %w", err)
	}

	// Parse package info JSON
	packageInfo, err := parsePackageInfoJson(responseJson)
	if err != nil {
		return nil, fmt.Errorf("unable to parse package info obtained from npm registry: %w", err)
	}
	return &packageInfo, nil
}

func formatNpmPackageInfoURL(cdxComponent schema.CDXComponent) (string, error) {
	// ex:"https://registry.npmjs.org/@babel/code-frame"
	requestURL, err := url.JoinPath(NPM_BASE_URL, cdxComponent.Group, cdxComponent.Name)
	if err != nil {
		return requestURL, fmt.Errorf("could not construct npm package info url: %w", err)
	}
	return requestURL, nil
}

func parsePackageInfoJson(packageInfoJson []byte) (packageInfo PackageInfo, err error) {
	if err := json.Unmarshal(packageInfoJson, &packageInfo); err != nil {
		return packageInfo, fmt.Errorf("unable to unmarshal license JSON: %w", err)
	}
	return
}

func extractLicenseFromNpmPackageInfo(packageInfo *PackageInfo) ([]schema.CDXLicenseChoice, error) {
	// Retrieve value of license attribute
	licenseString := packageInfo.License

	// Build license choices
	licenseChoices, err := licenseStringToLicenseChoices(licenseString)
	if err != nil {
		return nil, err
	}
	return licenseChoices, nil
}