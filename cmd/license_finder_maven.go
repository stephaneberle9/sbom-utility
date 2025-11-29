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
	REGEX_MAVEN_PURL = `^pkg:maven/[\w\._-]+/[\w\._-]+@[\w\.%_+-]+(\?(classifier=[\w%-\.]+&)?type=(jar|zip|pom))?$`

	MAVEN_CENTRAL_BASE_URL    = "https://repo1.maven.org/maven2"
	ITEMIS_MAVEN_BASE_URL     = "https://artifacts.itemis.cloud/repository/maven"
	ITEMIS_MAVEN_MPS_BASE_URL = "https://artifacts.itemis.cloud/repository/maven-mps"
	ITEMIS_MAVEN_MPS_PRERELEASES_BASE_URL = "https://artifacts.itemis.cloud/repository/maven-mps-prereleases"
)

var (
	// Maven repositories to search in order
	MAVEN_REPOSITORIES = []string{
		MAVEN_CENTRAL_BASE_URL,
		ITEMIS_MAVEN_BASE_URL,
		ITEMIS_MAVEN_MPS_BASE_URL,
		ITEMIS_MAVEN_MPS_PRERELEASES_BASE_URL,
	}
)

type MavenComponentLicenseFinderData struct {
	LicenseFinderData
}

// MavenMetadata represents the structure of maven-metadata.xml for SNAPSHOT versions
type MavenMetadata struct {
	Versioning struct {
		Snapshot struct {
			Timestamp   string `xml:"timestamp"`
			BuildNumber int    `xml:"buildNumber"`
		} `xml:"snapshot"`
		SnapshotVersions struct {
			SnapshotVersion []struct {
				Extension string `xml:"extension"`
				Value     string `xml:"value"`
			} `xml:"snapshotVersion"`
		} `xml:"snapshotVersions"`
	} `xml:"versioning"`
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
		version = fixUpVersion(groupId, artifactId, version)

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

func fixUpVersion(groupId, artifactId, version string) string {
	// 1.12.x -> 1.12.0, 1.12.+ -> 1.12.0
	for _, suffix := range []string{".x", ".+"} {
		if strings.HasSuffix(version, suffix) {
			return strings.TrimSuffix(version, suffix) + ".0"
		}
	}

	if groupId == "com.google.guava" {
		if artifactId == "guava" {
			// 32.1.1 -> 32.1.1-jre
			if !strings.HasSuffix(version, "-jre") && !strings.HasSuffix(version, "-android") {
				return fmt.Sprintf("%s-jre", version)
			}
		}
	}

	return version
}

func getPomFromMavenRepo(groupId, artifactId, version string) (*gopom.Project, error) {
	var lastErr error

	// Try each Maven repository in order until we find the POM
	for _, baseURL := range MAVEN_REPOSITORIES {
		pom, err := tryGetPomFromRepo(baseURL, groupId, artifactId, version)
		if err != nil {
			getLogger().Tracef("unable to fetch pom from %s: %v", baseURL, err)
			lastErr = err
			continue
		}
		if pom != nil {
			getLogger().Tracef("successfully fetched pom from %s", baseURL)
			return pom, nil
		}
	}

	// If we get here, none of the repositories had the POM
	if lastErr != nil {
		return nil, fmt.Errorf("unable to fetch pom from any Maven repository: %w", lastErr)
	}
	return nil, fmt.Errorf("unable to fetch pom from any Maven repository")
}

func tryGetPomFromRepo(baseURL, groupId, artifactId, version string) (*gopom.Project, error) {
	// Resolve SNAPSHOT version if needed
	// For SNAPSHOT versions, we need both the original version (for directory path) and resolved version (for filename)
	resolvedVersion := version

	if strings.HasSuffix(version, "-SNAPSHOT") {
		snapshotVersion, err := resolveSnapshotVersion(baseURL, groupId, artifactId, version)
		if err != nil {
			return nil, fmt.Errorf("unable to resolve SNAPSHOT version: %w", err)
		}
		resolvedVersion = snapshotVersion
		getLogger().Tracef("resolved SNAPSHOT version %s to %s from %s", version, resolvedVersion, baseURL)
	}

	// Compose Maven repository URL to be reached out to
	requestURL, err := formatMavenPomURL(baseURL, groupId, artifactId, version, resolvedVersion)
	if err != nil {
		return nil, fmt.Errorf("could not construct POM URL: %w", err)
	}
	getLogger().Tracef("trying to fetch pom from %s: %s", baseURL, requestURL)

	// Get pom from Maven repository
	responseXml, err := performHttpGetRequest(requestURL)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch pom: %w", err)
	}

	// Parse pom XML
	pom, err := parsePomXml(responseXml)
	if err != nil {
		return nil, fmt.Errorf("unable to parse pom: %w", err)
	}

	return &pom, nil
}

func resolveSnapshotVersion(baseURL, groupId, artifactId, version string) (string, error) {
	// Construct URL to maven-metadata.xml
	urlPath := strings.Split(groupId, ".")
	urlPath = append(urlPath, artifactId, version, "maven-metadata.xml")

	metadataURL, err := url.JoinPath(baseURL, urlPath...)
	if err != nil {
		return "", fmt.Errorf("could not construct maven-metadata.xml url: %w", err)
	}

	// Fetch maven-metadata.xml
	responseXml, err := performHttpGetRequest(metadataURL)
	if err != nil {
		return "", fmt.Errorf("unable to fetch maven-metadata.xml: %w", err)
	}

	// Parse maven-metadata.xml
	var metadata MavenMetadata
	decoder := xml.NewDecoder(bytes.NewReader(responseXml))
	decoder.CharsetReader = charset.NewReaderLabel
	if err := decoder.Decode(&metadata); err != nil {
		return "", fmt.Errorf("unable to unmarshal maven-metadata.xml: %w", err)
	}

	// Try to get version from snapshotVersions first (preferred method)
	for _, sv := range metadata.Versioning.SnapshotVersions.SnapshotVersion {
		if sv.Extension == "pom" {
			return sv.Value, nil
		}
	}

	// Fallback: construct version from timestamp and buildNumber
	if metadata.Versioning.Snapshot.Timestamp != "" {
		baseVersion := strings.TrimSuffix(version, "-SNAPSHOT")
		return fmt.Sprintf("%s-%s-%d", baseVersion, metadata.Versioning.Snapshot.Timestamp, metadata.Versioning.Snapshot.BuildNumber), nil
	}

	return "", fmt.Errorf("unable to resolve SNAPSHOT version from maven-metadata.xml")
}

func formatMavenPomURL(baseURL, groupID, artifactID, version, resolvedVersion string) (string, error) {
	// groupID needs to go from maven.org -> maven/org
	urlPath := strings.Split(groupID, ".")
	artifactPom := fmt.Sprintf("%s-%s.pom", artifactID, resolvedVersion)
	urlPath = append(urlPath, artifactID, version, artifactPom)

	// ex: "https://repo1.maven.org/maven2/groupID/artifactID/version/artifactID-resolvedVersion.pom
	requestURL, err := url.JoinPath(baseURL, urlPath...)
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
			// Handle cases where license has name, URL, or both
			if pomLicense.Name != nil {
				// Create appropriate license structure (expression, ID, or name) based on the license string format
				licenseChoice := licenseStringToLicenseChoice(*pomLicense.Name)

				// Add URL if available
				if pomLicense.URL != nil {
					if licenseChoice.License != nil {
						licenseChoice.License.Url = strings.TrimSpace(*pomLicense.URL)
					}
				}
				licenseChoices = append(licenseChoices, licenseChoice)
			} else if pomLicense.URL != nil {
				// Handle POM files that only have URL without name
				licenseChoice := schema.CDXLicenseChoice{
					License: &schema.CDXLicense{
						Url: strings.TrimSpace(*pomLicense.URL),
					},
				}
				licenseChoices = append(licenseChoices, licenseChoice)
			}
		}
	}
	return
}
