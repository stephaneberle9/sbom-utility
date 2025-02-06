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
	REGEX_NPM_PURL = `^pkg:npm/(@?[\w\._-]+/)?[\w\._-]+@[\w\._-]+$`

	NPM_BASE_URL = "https://registry.npmjs.org"
)

type PackageInfo struct {
	LicenseInfo
	Versions map[string]VersionInfo `json:"versions"`
}

type VersionInfo struct {
	LicenseInfo
}

type LicenseInfo struct {
	License  interface{}   `json:"license"`
	Licenses interface{}   `json:"licenses"`
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

	licenseChoices, err := extractLicensesFromNpmPackageInfo(packageInfo, cdxComponent)
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

func extractLicensesFromNpmPackageInfo(packageInfo *PackageInfo, cdxComponent schema.CDXComponent) ([]schema.CDXLicenseChoice, error) {
	var licenseInfos []interface{}
	
	collectLicenseInfos := func(licenseInfo LicenseInfo) {
		if licenseInfo.License != nil {
			// Check if license is an array or a single object
			if licenseInfoArray, exists := licenseInfo.License.([]interface{}); exists {
				// Collect all licenses from the array, e.g.,
				//
				// "license": [
				//   "MIT",
				//   "Apache2"
				// ]
				//
				licenseInfos = append(licenseInfos, licenseInfoArray...)
			} else {
				// Collect the single license object, e.g.,
				//
				// "license": "MIT"
				//
				licenseInfos = append(licenseInfos, licenseInfo.License)
			}
		} else if licenseInfo.Licenses != nil {
			// Check if licenses is an array or a single object
			if licenseInfoArray, exists := licenseInfo.Licenses.([]interface{}); exists {
				// Collect all licenses from the array, e.g.,
				//
				// "licenses": [
				//     {
				//         "type": "MIT",
				//         "url": "https://github.com/jonschlinkert/word-wrap/blob/master/LICENSE-MIT"
				//     }
				// ]
				//
				licenseInfos = append(licenseInfos, licenseInfoArray...)
			} else {
				// Collect the single license object, e.g.,
				//
				// "licenses": {
				//     "type": "MIT",
				//     "url": "https://github.com/jonschlinkert/word-wrap/blob/master/LICENSE-MIT"
				// }
				//
				licenseInfos = append(licenseInfos, licenseInfo.Licenses)
			}
		}
	}

	// Collect license infos from license/licenses attribute inside matching version info if any or directly from package info otherwise
	if versionInfo, exists := packageInfo.Versions[cdxComponent.Version]; exists {
		collectLicenseInfos(versionInfo.LicenseInfo)
	}
	if len(licenseInfos) == 0 {
		collectLicenseInfos(packageInfo.LicenseInfo)
	}
	if len(licenseInfos) == 0 {
		return nil, fmt.Errorf("package info for %s@%s contains not license information", cdxComponent.Name, cdxComponent.Version)
	}

	// Retrieve string values of license attributes if they are simple or that nested type attribute if they are complex
	var licenseStrings []string
	for _, licenseInfo := range licenseInfos {
		switch licenseInfo := licenseInfo.(type) {
		case string:
			licenseStrings = append(licenseStrings, licenseInfo)
		case map[string]interface{}:
			licenseType, ok := licenseInfo["type"].(string)
			if !ok {
				return nil, fmt.Errorf("license info for %s@%s has unexpected format", cdxComponent.Name, cdxComponent.Version)
			}
			licenseStrings = append(licenseStrings, licenseType)
		default:
			return nil, fmt.Errorf("license info for %s@%s has unexpected format", cdxComponent.Name, cdxComponent.Version)
		}
	}
	if len(licenseStrings) == 0 {
		return nil, fmt.Errorf("license for %s@%s not found", cdxComponent.Name, cdxComponent.Version)
	}

	// Build license choices
	licenseChoices, err := licenseStringsToLicenseChoices(licenseStrings)
	if err != nil {
		return nil, err
	}
	return licenseChoices, nil
}
