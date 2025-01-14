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
	"os"
	"io"
	"net/http"
	"net/url"
	"time"
	"regexp"

	"github.com/CycloneDX/sbom-utility/schema"
	"github.com/patrickmn/go-cache"

)

const (
	NPM_BASE_URL = "https://registry.npmjs.org"
)

const (
	REGEX_NPM_PURL = `^pkg:npm/@?[\w\._-]+/[\w\._-]+@[\w\._-]+$`
)

type PackageInfo struct {
	License string `json:"license"`
}

// compiled regexp. to save time
var npmPurlRegexp *regexp.Regexp

// "getter" for compiled regex expression
func getRegexForNpmPurl() (regex *regexp.Regexp, err error) {
	if npmPurlRegexp == nil {
		npmPurlRegexp, err = regexp.Compile(REGEX_NPM_PURL)
	}
	regex = npmPurlRegexp
	return
}

const (
	NPM_LICENSE_CACHE_FILENAME = ".npm-license-cache.dat"
)

var npmLicenseCache *cache.Cache

func StartupNpmLicenseDetector() {
	npmLicenseCache = cache.New(cache.NoExpiration, cache.NoExpiration)

	_, err := os.Stat(NPM_LICENSE_CACHE_FILENAME)
	if err == nil {
		if err := npmLicenseCache.LoadFile(NPM_LICENSE_CACHE_FILENAME); err != nil {
			getLogger().Errorf("Failed to load cache from file: %v", err)
		}
	}
}

func ShutdownNpmLicenseDetector() {
	if err := npmLicenseCache.SaveFile(NPM_LICENSE_CACHE_FILENAME); err != nil {
		getLogger().Errorf("Failed to save cache to file: %v", err)
	}
}

func IsFullyQualifiedNpmComponent(cdxComponent schema.CDXComponent) (result bool, err error) {
	regex, e := getRegexForNpmPurl()
	if e != nil {
		getLogger().Error(fmt.Errorf("unable to invoke regex. %v", e))
		err = e
		return
	}

	// Check if given component's package URL starts with 'pkg:npm' and contains complete group/artifact/version information
	result = regex.MatchString(cdxComponent.Purl)
	if !result {
		getLogger().Tracef("no fully qualified npm component: `%s`", cdxComponent.Purl)
	}
	return
}

func FindLicenseInNpmPackageInfo(cdxComponent schema.CDXComponent) (string, error) {
	startTime := time.Now()
	defer func() {
		elapsedTime := time.Since(startTime)
		getLogger().Tracef("FindLicenseInNpmPackageInfo() execution time: %s\n", elapsedTime)
	}()

	group := cdxComponent.Group
	name := cdxComponent.Name
	version := cdxComponent.Version

	packageId := fmt.Sprintf("%s:%s:%s", group, name, version)
	if npmLicenseCache != nil {
		if license, found := npmLicenseCache.Get(packageId); found {
			return license.(string), nil
		}
	}

	packageInfo, err := getPackageInfoFromNpmRegistry(group, name)
	if err != nil {
		return "", err
	}
	license := parseLicensesFromNpmPackageInfo(packageInfo)

	// Only cache actually found licenses to make sure that missing licenses can be searched for later on again
	if len(license) > 0 {
		if npmLicenseCache != nil {
			npmLicenseCache.Set(packageId, license, cache.NoExpiration)
		}
	}
	return license, nil
}

func getPackageInfoFromNpmRegistry(group, name string) (*PackageInfo, error) {
	// Compose npm registry URL to be reached out to
	requestURL, err := formatNpmPackageInfoURL(group, name)
	if err != nil {
		return nil, err
	}
	getLogger().Tracef("trying to fetch package info from npm registry %s", requestURL)

	// Sent HTTP GET request
	response, err := http.Get(requestURL)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := response.Body.Close(); err != nil {
			getLogger().Errorf("unable to close body: %+v", err)
		}
	}()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch package info: %s", response.Status)
	}

	// Read response body
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to read response data obtained from npm package registry: %w", err)
	}

	// Parse package info
	var packageInfo PackageInfo
	if err := json.Unmarshal(body, &packageInfo); err != nil {
		return nil, err
	}

	return &packageInfo, nil
}

func formatNpmPackageInfoURL(group, name string) (requestURL string, err error) {
	// ex:"https://registry.npmjs.org/@babel/code-frame"
	requestURL, err = url.JoinPath(NPM_BASE_URL, group, name)
	if err != nil {
		return requestURL, fmt.Errorf("could not construct npm package info url: %w", err)
	}
	return requestURL, err
}

func parseLicensesFromNpmPackageInfo(packageInfo *PackageInfo) string {
	return packageInfo.License
}
