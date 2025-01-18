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
	"net/url"
	"strings"
	"time"

	"github.com/CycloneDX/sbom-utility/schema"
	"github.com/vifraa/gopom"
	"golang.org/x/net/html/charset"
)

const (
	// Matches component package URLs starting with 'pkg:maven', containing complete group/artifact/version information,
	// and matching one of the Maven core packaging types
	REGEX_MAVEN_PURL = `^pkg:maven/[\w\._-]+/[\w\._-]+@[\w\._-]+(\?(classifier=[\w%-\.]+&)?type=(jar|zip|pom))?$`

	MAVEN_BASE_URL = "https://repo1.maven.org/maven2"
)

type MavenComponentLicenseFinderData struct {
	LicenseFinderData
}

var MavenComponentLicenseFinder *MavenComponentLicenseFinderData = &MavenComponentLicenseFinderData{
	LicenseFinderData: LicenseFinderData{
		licenseCacheFileName: ".maven-license-cache.dat",
		purlRegexpString:     REGEX_MAVEN_PURL,
	},
}

func (finder *MavenComponentLicenseFinderData) FindLicenses(cdxComponent schema.CDXComponent) ([]schema.CDXLicenseChoice, error) {
	startTime := time.Now()
	defer func() {
		elapsedTime := time.Since(startTime)
		getLogger().Tracef("FindLicenses() execution time: %s\n", elapsedTime)
	}()

	if licenseChoices, found := finder.retrieveFromLicenseCache(cdxComponent); found {
		return licenseChoices, nil
	}

	groupId := cdxComponent.Group
	artifactId := cdxComponent.Name
	version := cdxComponent.Version

	// The given component may be nested into parent components, we'll recursively check for licenseChoices until we find any
	var licenseChoices []schema.CDXLicenseChoice
	for {
		pom, err := getPomFromMavenRepo(groupId, artifactId, version)
		if err != nil {
			return nil, err
		}

		licenseChoices = extractLicensesFromPom(pom)
		if len(licenseChoices) > 0 || pom == nil || pom.Parent == nil {
			break
		}

		groupId = *pom.Parent.GroupID
		artifactId = *pom.Parent.ArtifactID
		version = *pom.Parent.Version
	}

	finder.storeInLicenseCache(cdxComponent, licenseChoices)

	return licenseChoices, nil
}

func getPomFromMavenRepo(groupId, artifactId, version string) (*gopom.Project, error) {
	// Compose Maven central URL to be reached out to
	requestURL, err := formatMavenPomURL(groupId, artifactId, version)
	if err != nil {
		return nil, err
	}
	getLogger().Tracef("trying to fetch pom from Maven central %s", requestURL)

	// Get pom from Maven central
	responseXml, err := performHttpGetRequest(requestURL)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch pom from Maven central: %w", err)
	}

	// Parse pom XML
	pom, err := parsePomXml(responseXml)
	if err != nil {
		return nil, fmt.Errorf("unable to parse pom obtained from Maven central: %w", err)
	}
	return &pom, nil
}

func formatMavenPomURL(groupID, artifactID, version string) (string, error) {
	// groupID needs to go from maven.org -> maven/org
	urlPath := strings.Split(groupID, ".")
	artifactPom := fmt.Sprintf("%s-%s.pom", artifactID, version)
	urlPath = append(urlPath, artifactID, version, artifactPom)

	// ex:"https://repo1.maven.org/maven2/groupID/artifactID/artifactPom
	requestURL, err := url.JoinPath(MAVEN_BASE_URL, urlPath...)
	if err != nil {
		return requestURL, fmt.Errorf("could not construct maven pom url: %w", err)
	}
	return requestURL, nil
}

func parsePomXml(pomXml []byte) (pomProject gopom.Project, err error) {
	decoder := xml.NewDecoder(bytes.NewReader(pomXml))
	// when an xml file has a character set declaration (e.g. '<?xml version="1.0" encoding="ISO-8859-1"?>') read that and use the correct decoder
	decoder.CharsetReader = charset.NewReaderLabel
	if err := decoder.Decode(&pomProject); err != nil {
		return pomProject, fmt.Errorf("unable to unmarshal pom.xml: %w", err)
	}
	return
}

func extractLicensesFromPom(pom *gopom.Project) (licenseChoices []schema.CDXLicenseChoice) {
	if pom != nil && pom.Licenses != nil {
		for _, pomLicense := range *pom.Licenses {
			licenseChoice := schema.CDXLicenseChoice{
				License: &schema.CDXLicense{},
			}
			if pomLicense.Name != nil {
				licenseChoice.License.Name = *pomLicense.Name
			}
			if pomLicense.URL != nil {
				licenseChoice.License.Url = *pomLicense.URL
			}
			licenseChoices = append(licenseChoices, licenseChoice)
		}
	}
	return
}
