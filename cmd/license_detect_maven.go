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
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/CycloneDX/sbom-utility/schema"
	"github.com/patrickmn/go-cache"
	"github.com/saintfish/chardet"
	"github.com/vifraa/gopom"
	"golang.org/x/net/html/charset"

)

const (
	MAVEN_BASE_URL                     = "https://repo1.maven.org/maven2"
	MAX_PARENT_PACKAGE_RECURSION_DEPTH = 5
)

const (
	REGEX_MAVEN_PURL = `^pkg:maven/[\w\._-]+/[\w\._-]+@[\w\._-]+(\?(classifier=[\w%-\.]+&)?type=(jar|zip|pom))?$`
)

// compiled regexp. to save time
var mavenPurlRegexp *regexp.Regexp

// "getter" for compiled regex expression
func getRegexForMavenPurl() (regex *regexp.Regexp, err error) {
	if mavenPurlRegexp == nil {
		mavenPurlRegexp, err = regexp.Compile(REGEX_MAVEN_PURL)
	}
	regex = mavenPurlRegexp
	return
}

const (
	MAVEN_LICENSE_CACHE_FILENAME = ".maven-license-cache.dat"
)

var mavenLicenseCache *cache.Cache

func StartupMavenLicenseDetector() {
	mavenLicenseCache = cache.New(cache.NoExpiration, cache.NoExpiration)

	_, err := os.Stat(MAVEN_LICENSE_CACHE_FILENAME)
	if err == nil {
		if err := mavenLicenseCache.LoadFile(MAVEN_LICENSE_CACHE_FILENAME); err != nil {
			getLogger().Errorf("Failed to load cache from file: %v", err)
		}
	}
}

func ShutdownMavenLicenseDetector() {
	if err := mavenLicenseCache.SaveFile(MAVEN_LICENSE_CACHE_FILENAME); err != nil {
		getLogger().Errorf("Failed to save cache to file: %v", err)
	}
}

func IsFullyQualifiedMavenComponent(cdxComponent schema.CDXComponent) (result bool, err error) {
	regex, e := getRegexForMavenPurl()
	if e != nil {
		getLogger().Error(fmt.Errorf("unable to invoke regex. %v", e))
		err = e
		return
	}

	// Check if given component's package URL starts with 'pkg:maven', contains complete group/artifact/version information, and matches one of the Maven core packaging types
	result = regex.MatchString(cdxComponent.Purl)
	if !result {
		getLogger().Tracef("no fully qualified maven component: `%s`", cdxComponent.Purl)
	}
	return
}

func FindLicensesInPom(cdxComponent schema.CDXComponent) ([]string, error) {
	startTime := time.Now()
	defer func() {
		elapsedTime := time.Since(startTime)
		getLogger().Tracef("FindLicensesInPom() execution time: %s\n", elapsedTime)
	}()

	groupID := cdxComponent.Group
	artifactID := cdxComponent.Name
	version := cdxComponent.Version

	componentId := fmt.Sprintf("%s:%s:%s", groupID, artifactID, version)
	if licenses, found := mavenLicenseCache.Get(componentId); found {
		return licenses.([]string), nil
	}

	// The given component may be nested into parent components, we'll recursively check for licenses until we reach the max depth
	var licenses []string
	for i := 0; i < MAX_PARENT_PACKAGE_RECURSION_DEPTH; i++ {
		pom, err := getPomFromMavenRepo(groupID, artifactID, version)
		if err != nil {
			return nil, err
		}
		licenses = parseLicensesFromPom(pom)
		if len(licenses) > 0 || pom == nil || pom.Parent == nil {
			break
		}

		groupID = *pom.Parent.GroupID
		artifactID = *pom.Parent.ArtifactID
		version = *pom.Parent.Version
	}

	// Only cache actually found licenses to make sure that missing licenses can be searched for later on again
	if len(licenses) > 0 {
		mavenLicenseCache.Set(componentId, licenses, cache.NoExpiration)
	}
	return licenses, nil
}

func getPomFromMavenRepo(groupID, artifactID, version string) (*gopom.Project, error) {
	// Compose Maven central URL to be reached out to
	requestURL, err := formatMavenPomURL(groupID, artifactID, version)
	if err != nil {
		return nil, err
	}
	getLogger().Tracef("trying to fetch pom from Maven central %s", requestURL)

	// Create an HTTP GET request
	request, err := http.NewRequest(http.MethodGet, requestURL, nil)
	if err != nil {
		return nil, fmt.Errorf("unable to create request for Maven central: %w", err)
	}

	// Sent HTTP GET request
	httpClient := &http.Client{
		Timeout: time.Second * 10,
	}
	response, err := httpClient.Do(request)
	if err != nil || response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unable to get pom from Maven central: %w", err)
	}
	defer func() {
		if err := response.Body.Close(); err != nil {
			getLogger().Errorf("unable to close body: %+v", err)
		}
	}()

	// Read response body
	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to read response data obtained from Maven central: %w", err)
	}

	// Parse pom
	pom, err := decodePomXML(strings.NewReader(string(responseBody)))
	if err != nil {
		return nil, fmt.Errorf("unable to parse pom obtained from Maven central: %w", err)
	}

	return &pom, nil
}

func parseLicensesFromPom(pom *gopom.Project) []string {
	var licenses []string
	if pom != nil && pom.Licenses != nil {
		for _, license := range *pom.Licenses {
			if license.Name != nil {
				licenses = append(licenses, *license.Name)
			} else {
				licenses = append(licenses, "")
			}
			if license.URL != nil {
				licenses = append(licenses, *license.URL)
			} else {
				licenses = append(licenses, "")
			}
		}
	}
	return licenses
}

func formatMavenPomURL(groupID, artifactID, version string) (requestURL string, err error) {
	// groupID needs to go from maven.org -> maven/org
	urlPath := strings.Split(groupID, ".")
	artifactPom := fmt.Sprintf("%s-%s.pom", artifactID, version)
	urlPath = append(urlPath, artifactID, version, artifactPom)

	// ex:"https://repo1.maven.org/maven2/groupID/artifactID/artifactPom
	requestURL, err = url.JoinPath(MAVEN_BASE_URL, urlPath...)
	if err != nil {
		return requestURL, fmt.Errorf("could not construct maven url: %w", err)
	}
	return requestURL, err
}

func decodePomXML(content io.Reader) (project gopom.Project, err error) {
	inputReader, err := getUtf8Reader(content)
	if err != nil {
		return project, fmt.Errorf("unable to read pom.xml: %w", err)
	}

	decoder := xml.NewDecoder(inputReader)
	// when an xml file has a character set declaration (e.g. '<?xml version="1.0" encoding="ISO-8859-1"?>') read that and use the correct decoder
	decoder.CharsetReader = charset.NewReaderLabel

	if err := decoder.Decode(&project); err != nil {
		return project, fmt.Errorf("unable to unmarshal pom.xml: %w", err)
	}

	return project, nil
}

func getUtf8Reader(content io.Reader) (io.Reader, error) {
	pomContents, err := io.ReadAll(content)
	if err != nil {
		return nil, err
	}

	detector := chardet.NewTextDetector()
	detection, err := detector.DetectBest(pomContents)

	var inputReader io.Reader
	if err == nil && detection != nil {
		if detection.Charset == "UTF-8" {
			inputReader = bytes.NewReader(pomContents)
		} else {
			inputReader, err = charset.NewReaderLabel(detection.Charset, bytes.NewReader(pomContents))
			if err != nil {
				return nil, fmt.Errorf("unable to get encoding: %w", err)
			}
		}
	} else {
		// we could not detect the encoding, but we want a valid file to read. Replace unreadable
		// characters with the UTF-8 replacement character.
		inputReader = strings.NewReader(strings.ToValidUTF8(string(pomContents), "�"))
	}
	return inputReader, nil
}
