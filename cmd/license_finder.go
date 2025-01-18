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
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"

	"github.com/CycloneDX/sbom-utility/schema"
	"github.com/patrickmn/go-cache"
)

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

func performHttpGetRequest(requestURL string) ([]byte, error) {
	// Send HTTP GET request
	response, err := http.Get(requestURL)
	if err != nil {
		return nil, fmt.Errorf("failed to send HTTP GET request to %s: %w", requestURL, err)
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP GET request failed: %w", err)
	}

	// Read response body
	defer func() {
		if err := response.Body.Close(); err != nil {
			getLogger().Errorf("unable to close response body: %+v", err)
		}
	}()
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

	// Send HTTP Post request
	response, err := http.Post(requestURL, "application/x-www-form-urlencoded", bytes.NewBufferString(requestForm.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to send HTTP POST request to %s: %w", requestURL, err)
	}
	defer func() {
		if err := response.Body.Close(); err != nil {
			getLogger().Errorf("unable to close response body: %+v", err)
		}
	}()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP POST request failed: %w", err)
	}

	// Read response body
	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to read response body: %w", err)
	}
	return responseBody, nil
}

func licenseStringToLicenseChoices(licenseString string) (licenseChoices []schema.CDXLicenseChoice, err error) {
	regex, err := getRegexForLicenseExpression()
	if err != nil {
		getLogger().Error(fmt.Errorf("unable to invoke regex. %v", err))
		return
	}

	if regex.MatchString(licenseString) {
		licenseChoices = []schema.CDXLicenseChoice{
			{
				CDXLicenseExpression: schema.CDXLicenseExpression{
					Expression: licenseString,
				},
			},
		}
	} else {
		licenseChoices = []schema.CDXLicenseChoice{
			{
				License: &schema.CDXLicense{
					Id: licenseString,
				},
			},
		}
	}
	return
}
