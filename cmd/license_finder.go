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
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
	"regexp"

	"github.com/CycloneDX/sbom-utility/schema"
	"github.com/patrickmn/go-cache"

)

const (
	// Host of the itemis Nexus Repository Manager instance. Requests targeting this
	// host are sent with Basic Auth credentials (NEXUS_USER / NEXUS_PASS) when set,
	// so that components in private (non-anonymous) repositories can be resolved.
	NEXUS_HOST = "artifacts.itemis.cloud"

	NEXUS_USER_ENV_VAR = "NEXUS_USER"
	NEXUS_PASS_ENV_VAR = "NEXUS_PASS"
)

// httpClient is the shared client used for all license-lookup requests. It sets
// a bounded timeout so that a single stalled repository cannot block a lookup
// indefinitely (the finders sweep several repositories sequentially).
var httpClient = &http.Client{
	Timeout: 30 * time.Second,
}

type LicenseFinder interface {
	Startup()
	Shutdown()
	IsApplicable(cdxComponent schema.CDXComponent) (bool, error)
	FindLicenses(cdxComponent schema.CDXComponent) ([]schema.CDXLicenseChoice, error)
}

type LicenseFinderData struct {
	// Configuration
	licenseCacheFileName string
	purlRegexpString     string

	// State
	licenseCache *cache.Cache
	purlRegexp   *regexp.Regexp
}

func (finder *LicenseFinderData) Startup() {
	// Register the []schema.CDXLicenseChoice type with gob
	// so that it can be serialized/deserialized in the license cache
	gob.Register([]schema.CDXLicenseChoice{})

	finder.licenseCache = cache.New(cache.NoExpiration, cache.NoExpiration)

	_, err := os.Stat(finder.licenseCacheFileName)
	if err == nil {
		if err := finder.licenseCache.LoadFile(finder.licenseCacheFileName); err != nil {
			getLogger().Errorf("failed to load cache from file: %v", err)
		}
	}
}

func (finder *LicenseFinderData) Shutdown() {
	if finder.licenseCache == nil {
		getLogger().Errorf("unable to shutdown license finder because it has never been started up")
		return
	}

	if err := finder.licenseCache.SaveFile(finder.licenseCacheFileName); err != nil {
		getLogger().Errorf("failed to save cache to file: %v", err)
	}
}

func (finder *LicenseFinderData) IsApplicable(cdxComponent schema.CDXComponent) (bool, error) {
	if finder.purlRegexp == nil {
		purlRegexp, err := regexp.Compile(finder.purlRegexpString)
		if err != nil {
			return false, fmt.Errorf("unable to compile regexp: %w", err)
		}
		finder.purlRegexp = purlRegexp
	}
	return finder.purlRegexp.MatchString(cdxComponent.Purl), nil
}

func getComponentLicenseCacheId(cdxComponent schema.CDXComponent) string {
	return fmt.Sprintf("%s:%s:%s", cdxComponent.Group, cdxComponent.Name, cdxComponent.Version)
}

func (finder *LicenseFinderData) retrieveFromLicenseCache(cdxComponent schema.CDXComponent) ([]schema.CDXLicenseChoice, bool) {
	if finder.licenseCache != nil {
		licenseCacheId := getComponentLicenseCacheId(cdxComponent)
		if cachedLicenseChoices, found := finder.licenseCache.Get(licenseCacheId); found {
			return cachedLicenseChoices.([]schema.CDXLicenseChoice), true
		}
	}
	return nil, false
}

func (finder *LicenseFinderData) storeInLicenseCache(cdxComponent schema.CDXComponent, licenseChoices []schema.CDXLicenseChoice) {
	// Only cache actually found licenses to make sure that missing licenses can be searched for later on again
	if len(licenseChoices) > 0 {
		if finder.licenseCache != nil {
			licenseCacheId := getComponentLicenseCacheId(cdxComponent)
			finder.licenseCache.Set(licenseCacheId, licenseChoices, cache.NoExpiration)
		}
	}
}

// HttpStatusError is returned when an HTTP request completes but the server
// responds with a non-2xx status code. It carries the status code so that
// callers can distinguish, for example, an authentication failure (401/403)
// from a missing artifact (404).
type HttpStatusError struct {
	URL        string
	StatusCode int
}

func (e *HttpStatusError) Error() string {
	return fmt.Sprintf("HTTP request to %s returned status code %d", e.URL, e.StatusCode)
}

// isAuthError reports whether err (or any error it wraps) is an HTTP
// authentication/authorization failure (401 Unauthorized or 403 Forbidden).
func isAuthError(err error) bool {
	var statusErr *HttpStatusError
	if errors.As(err, &statusErr) {
		return statusErr.StatusCode == http.StatusUnauthorized || statusErr.StatusCode == http.StatusForbidden
	}
	return false
}

// addNexusAuthIfApplicable adds Basic Auth credentials to the request when it
// targets the itemis Nexus host and the NEXUS_USER / NEXUS_PASS env vars are set.
// Credentials are never attached to requests to other hosts (e.g. Maven Central,
// the npm registry, or the Eclipse license check service).
func addNexusAuthIfApplicable(request *http.Request) {
	if !strings.EqualFold(request.URL.Hostname(), NEXUS_HOST) {
		return
	}
	user := os.Getenv(NEXUS_USER_ENV_VAR)
	pass := os.Getenv(NEXUS_PASS_ENV_VAR)
	if user != "" && pass != "" {
		request.SetBasicAuth(user, pass)
	}
}

func performHttpGetRequest(requestURL string) ([]byte, error) {
	// Build HTTP GET request
	request, err := http.NewRequest(http.MethodGet, requestURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP GET request for %s: %w", requestURL, err)
	}

	// Authenticate against the itemis Nexus when applicable
	addNexusAuthIfApplicable(request)

	// Send HTTP GET request
	response, err := httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("failed to send HTTP GET request to %s: %w", requestURL, err)
	}
	defer func() {
		if err := response.Body.Close(); err != nil {
			getLogger().Errorf("unable to close response body: %+v", err)
		}
	}()
	if response.StatusCode != http.StatusOK {
		return nil, &HttpStatusError{URL: requestURL, StatusCode: response.StatusCode}
	}

	// Read response body
	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to read response body: %w", err)
	}
	return responseBody, nil
}

func performHttpPostFormRequest(requestURL, formDataKey string, formData []byte) ([]byte, error) {
	// Convert JSON body to URL-encoded form
	requestForm := url.Values{}
	requestForm.Add(formDataKey, string(formData))

	// Build HTTP POST request
	request, err := http.NewRequest(http.MethodPost, requestURL, bytes.NewBufferString(requestForm.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP POST request for %s: %w", requestURL, err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Authenticate against the itemis Nexus when applicable
	addNexusAuthIfApplicable(request)

	// Send HTTP Post request
	response, err := httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("failed to send HTTP POST request to %s: %w", requestURL, err)
	}
	defer func() {
		if err := response.Body.Close(); err != nil {
			getLogger().Errorf("unable to close response body: %+v", err)
		}
	}()
	if response.StatusCode != http.StatusOK {
		return nil, &HttpStatusError{URL: requestURL, StatusCode: response.StatusCode}
	}

	// Read response body
	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to read response body: %w", err)
	}
	return responseBody, nil
}

func licenseStringsToLicenseChoices(licenseStrings []string) (licenseChoices []schema.CDXLicenseChoice, err error) {
	for _, licenseString := range licenseStrings {
		licenseChoices = append(licenseChoices, licenseStringToLicenseChoice(licenseString))
	}
	return
}

// Converts a single license string into a CDXLicenseChoice based on its structure:
// - If it's a license expression (contains operators like AND, OR), creates a license expression
// - If it's a valid SPDX ID, creates a license with an ID
// - Otherwise, creates a license with a name
func licenseStringToLicenseChoice(licenseString string) schema.CDXLicenseChoice {
	cleanedLicenseString := strings.TrimSpace(licenseString)

	if schema.IsLicenseExpression(cleanedLicenseString) {
		return schema.CDXLicenseChoice{
			CDXLicenseExpression: schema.CDXLicenseExpression{
				Expression: cleanedLicenseString,
			},
		}
	}

	if schema.IsValidSpdxId(cleanedLicenseString) {
		return schema.CDXLicenseChoice{
			License: &schema.CDXLicense{
				Id: cleanedLicenseString,
			},
		}
	}

	return schema.CDXLicenseChoice{
		License: &schema.CDXLicense{
			Name: cleanedLicenseString,
		},
	}
}
