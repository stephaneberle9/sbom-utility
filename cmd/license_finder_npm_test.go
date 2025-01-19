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
	"testing"

	"github.com/CycloneDX/sbom-utility/schema"

)

// -------------------------------------------
// license test helper functions
// -------------------------------------------

func innerTestIsApplicableToNpmComponent(t *testing.T, purl string, expectedResult bool) {
	t.Logf("PURL under test: `%s`", purl)

	var err error
	cdxComponent := schema.CDXComponent{
		Purl: purl,
	}

	result, err := NpmComponentLicenseFinder.IsApplicable(cdxComponent)
	if err != nil {
		t.Errorf("unable to determine if given component is a npm component: `%v`: `%s`\n", cdxComponent, err.Error())
		return
	}

	if result != expectedResult {
		t.Errorf("Is npm component: expected `%t`, actual `%t`\n",
			expectedResult, result)
		return
	}
}

func innerTestFindLicenseOfNpmComponent(t *testing.T, group string, name string, version string, expectedLicense string) {
	t.Logf("Component under test: `%s:%s:%s`", group, name, version)

	var err error
	cdxComponent := schema.CDXComponent{
		Group:   group,
		Name:    name,
		Version: version,
	}

	licenseChoices, err := NpmComponentLicenseFinder.FindLicenses(cdxComponent)
	if err != nil {
		t.Errorf("unable to find package info of component `%v`: `%s`\n", cdxComponent, err.Error())
		return
	}
	if len(licenseChoices) == 0 {
		t.Errorf("no license found in package info of component `%v`\n", cdxComponent)
		return
	}
	if len(licenseChoices) > 1 {
		t.Errorf("to many licenses found in POM of component `%v`\n", cdxComponent)
		return
	}

	regex, err := getRegexForLicenseExpression()
	if err != nil {
		t.Errorf("unable to invoke regex. %v", err)
		return
	}
	if regex.MatchString(expectedLicense) {
		if licenseChoices[0].Expression != expectedLicense {
			t.Errorf("License: expected `%s`, actual `%s`\n",
				expectedLicense, licenseChoices[0].Expression)
			return
		}
	} else {
		if licenseChoices[0].License.Id != expectedLicense {
			t.Errorf("License: expected `%s`, actual `%s`\n",
				expectedLicense, licenseChoices[0].License.Id)
			return
		}
	}
}

// ------------------------------------
// P2 component license detection tests
// ------------------------------------

func TestIsApplicableToNpmComponent(t *testing.T) {
	PURL := "pkg:npm/express@5.0.1"
	innerTestIsApplicableToNpmComponent(t, PURL, true)

	PURL = "pkg:npm/abbrev@2.0.0"
	innerTestIsApplicableToNpmComponent(t, PURL, true)

	PURL = "pkg:npm/boolbase@1.0.0"
	innerTestIsApplicableToNpmComponent(t, PURL, true)

	PURL = "pkg:npm/@babel/code-frame@7.24.7"
	innerTestIsApplicableToNpmComponent(t, PURL, true)

	PURL = "pkg:npm/@babel/helper-validator-identifier@7.24.7"
	innerTestIsApplicableToNpmComponent(t, PURL, true)

	PURL = "pkg:npm/@babel/highlight@7.24.7"
	innerTestIsApplicableToNpmComponent(t, PURL, true)
}

func TestFindLicenseOfNpmComponent(t *testing.T) {
	GROUP := ""
	NAME := "abbrev"
	VERSION := "2.0.0"
	EXPECTED_LICENSE := "ISC"
	innerTestFindLicenseOfNpmComponent(t, GROUP, NAME, VERSION, EXPECTED_LICENSE)

	GROUP = ""
	NAME = "boolbase"
	VERSION = "1.0.0"
	EXPECTED_LICENSE = "ISC"
	innerTestFindLicenseOfNpmComponent(t, GROUP, NAME, VERSION, EXPECTED_LICENSE)

	GROUP = ""
	NAME = "express"
	VERSION = "5.0.1"
	EXPECTED_LICENSE = "MIT"
	innerTestFindLicenseOfNpmComponent(t, GROUP, NAME, VERSION, EXPECTED_LICENSE)

	GROUP = ""
	NAME = "config-chain"
	VERSION = "1.1.13"
	EXPECTED_LICENSE = "MIT"
	innerTestFindLicenseOfNpmComponent(t, GROUP, NAME, VERSION, EXPECTED_LICENSE)

	GROUP = ""
	NAME = "memorystream"
	VERSION = "0.3.1"
	EXPECTED_LICENSE = "MIT"
	innerTestFindLicenseOfNpmComponent(t, GROUP, NAME, VERSION, EXPECTED_LICENSE)

	GROUP = ""
	NAME = "string-width-cjs"
	VERSION = "4.2.3"
	EXPECTED_LICENSE = "ISC"
	innerTestFindLicenseOfNpmComponent(t, GROUP, NAME, VERSION, EXPECTED_LICENSE)

	GROUP = "@babel"
	NAME = "code-frame"
	VERSION = "7.24.7"
	EXPECTED_LICENSE = "MIT"
	innerTestFindLicenseOfNpmComponent(t, GROUP, NAME, VERSION, EXPECTED_LICENSE)
}
