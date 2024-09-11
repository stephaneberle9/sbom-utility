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
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"time"

	"github.com/CycloneDX/sbom-utility/schema"

)

const (
	ECLIPSE_LICENSE_CHECK_SERVICE_URL = "https://www.eclipse.org/projects/services/license_check.php"
)

const (
	REGEX_P2_PURL = `^pkg:maven/p2\.[\w\._-]+/[\w\._-]+@[\w\._-]+\?(classifier=[\w%-\.]+&)?type=(eclipse-plugin|eclipse-feature|p2-installable-unit)$`
	REGEX_LICENSE_REF_EXPRESSION = `(\s+(AND|OR|WITH)\s+LicenseRef-[\w\.-]+)+`
)

// compiled regexp. to save time
var p2PurlRegexp *regexp.Regexp
var licenseRefExpressionRegexp *regexp.Regexp

// "getter" for compiled regex expression
func getRegexForP2Purl() (regex *regexp.Regexp, err error) {
	if p2PurlRegexp == nil {
		p2PurlRegexp, err = regexp.Compile(REGEX_P2_PURL)
	}
	regex = p2PurlRegexp
	return
}

// "getter" for compiled regex expression
func getRegexForLicenseRefExpression() (regex *regexp.Regexp, err error) {
	if licenseRefExpressionRegexp == nil {
		licenseRefExpressionRegexp, err = regexp.Compile(REGEX_LICENSE_REF_EXPRESSION)
	}
	regex = licenseRefExpressionRegexp
	return
}

func IsFullyQualifiedP2Component(cdxComponent schema.CDXComponent) (result bool, err error) {
	regex, e := getRegexForP2Purl()
	if e != nil {
		getLogger().Error(fmt.Errorf("unable to invoke regex. %v", e))
		err = e
		return
	}

	// Check if given component's package URL starts with 'pkg:maven/p2', contains complete group/artifact/version information, and matches one of the Eclipse p2 packaging types
	result = regex.MatchString(cdxComponent.Purl)
	if !result {
		getLogger().Tracef("no fully qualified p2 component: `%s`", cdxComponent.Purl)
	}
	return
}

func QueryEclipseLicenseCheckService(cdxComponent schema.CDXComponent) (string, error) {
	startTime := time.Now()

	var license string

	groupID := cdxComponent.Group
	artifactID := cdxComponent.Name
	version := cdxComponent.Version

	licenseData, err := invokeEclipseLicenseCheckService(groupID, artifactID, version)
	if err != nil {
		return "", err
	}
	license = parseLicensesFromEclipseLicenseData(licenseData)

	// Ignore proprietary licenses prefixed by LicenseRef- from license expressions if any
	regex, err := getRegexForLicenseRefExpression()
	if err != nil {
		getLogger().Error(fmt.Errorf("unable to invoke regex. %v", err))
		return "", err
	}
	license = regex.ReplaceAllString(license, "")

	elapsedTime := time.Since(startTime)
	getLogger().Tracef("QueryEclipseLicenseCheckService() execution time: %s\n", elapsedTime)

	return license, nil
}

func invokeEclipseLicenseCheckService(groupID, artifactID, version string) (*map[string]interface{}, error) {
	// Create JSON body to be sent
	requestJson := map[string]interface{}{
		"dependencies": []string{fmt.Sprintf("p2/orbit/%s/%s/%s", groupID, artifactID, version)},
	}
	requestJsonData, err := json.Marshal(requestJson)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal JSON: %v", err)
	}

	// Convert JSON body to URL-encoded form
	requestForm := url.Values{}
	requestForm.Add("request", string(requestJsonData))

	// Create an HTTP POST request
	request, err := http.NewRequest(http.MethodPost, ECLIPSE_LICENSE_CHECK_SERVICE_URL, bytes.NewBufferString(requestForm.Encode()))
	if err != nil {
		return nil, fmt.Errorf("unable to create request for Eclipse license check service : %w", err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Send HTTP POST request
	httpClient := &http.Client{
		Timeout: time.Second * 10,
	}
	response, err := httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("unable to obtain license data from Eclipse license check service: %w", err)
	}
	defer func() {
		if err := response.Body.Close(); err != nil {
			getLogger().Errorf("unable to close body: %+v", err)
		}
	}()

	// Read response body
	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to read response data obtained from Eclipse license check service: %w", err)
	}

	// Parse license data
	var licenseData map[string]interface{}
	if err := json.Unmarshal(responseBody, &licenseData); err != nil {
		return nil, fmt.Errorf("unable to parse license data obtained from Eclipse license check service: %w", err)
	}
	return &licenseData, nil
}

func parseLicensesFromEclipseLicenseData(licenseData *map[string]interface{}) string {
	// Retrieve value of license attribute in license data of first (and only) approved component
	var license string
	if approved, ok := (*licenseData)["approved"].(map[string]interface{}); ok {
		for _, component := range approved {
			if licenseInfo, ok := component.(map[string]interface{}); ok {
				if licenseId, ok := licenseInfo["license"].(string); ok {
					license = licenseId
				}
			}
		}
	}
	return license
}