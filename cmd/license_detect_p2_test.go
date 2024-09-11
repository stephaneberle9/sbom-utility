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

func innerTestIsFullyQualifiedP2Component(t *testing.T, purl string, expectedResult bool) {
	t.Logf("PURL under test: `%s`", purl)

	var err error
	cdxComponent := schema.CDXComponent{
		Purl:   purl,
	}

	result, err := IsFullyQualifiedP2Component(cdxComponent)
	if err != nil {
		t.Errorf("unable to determine if given component is a p2 component: `%v`: `%s`\n", cdxComponent, err.Error())
		return
	}

	if result != expectedResult {
		t.Errorf("Is p2 component: expected `%t`, actual `%t`\n",
		expectedResult, result)
		return
	}
}

func innerTestQueryEclipseLicenseCheckService(t *testing.T, group string, name string, version string, expectedLicense string) {
	t.Logf("Component under test: `%s:%s:%s`", group, name, version)

	var err error
	cdxComponent := schema.CDXComponent{
		Group:   group,
		Name:    name,
		Version: version,
	}

	license, err := QueryEclipseLicenseCheckService(cdxComponent)
	if err != nil {
		t.Errorf("unable to query license of component `%v`: `%s`\n", cdxComponent, err.Error())
		return
	}
	if len(license) == 0 {
		t.Errorf("no license found for component `%v`\n", cdxComponent)
		return
	}
	t.Logf("license: `%s`", license)

	if license != expectedLicense {
		t.Errorf("License: expected `%s`, actual `%s`\n",
			expectedLicense, license)
		return
	}
}

// ------------------------------------
// P2 component license detection tests
// ------------------------------------

func TestIsFullyQualifiedP2Component(t *testing.T) {
	PURL := "pkg:maven/p2.eclipse.plugin/org.apache.ant@1.10.12.v20211102-1452?type=eclipse-plugin"
	innerTestIsFullyQualifiedP2Component(t, PURL, true)

	PURL = "pkg:maven/p2.eclipse.plugin/org.apache.ant@1.10.12.v20211102-1452?classifier=lib%2Fant-apache-bcel.jar&type=eclipse-plugin"
	innerTestIsFullyQualifiedP2Component(t, PURL, true)

	PURL = "pkg:maven/org.apache.ant/ant@1.10.6?type=jar"
	innerTestIsFullyQualifiedP2Component(t, PURL, false)

	PURL = "pkg:maven/org.apache.ant/ant@1.10.6?classifier=lib%2Fant-apache-bcel.jar&type=jar"
	innerTestIsFullyQualifiedP2Component(t, PURL, false)
}

func TestQueryEclipseLicenseCheckService(t *testing.T) {
	GROUP := "p2.eclipse.plugin"
	NAME := "org.hamcrest.core"
	VERSION := "1.3.0.v20180420-1519"
	EXPECTED_LICENSE := "BSD-2-Clause"
	innerTestQueryEclipseLicenseCheckService(t, GROUP, NAME, VERSION, EXPECTED_LICENSE)

	GROUP = "p2.eclipse.plugin"
	NAME = "org.hamcrest.core"
	VERSION = "1.3.0"
	EXPECTED_LICENSE = "BSD-2-Clause"
	innerTestQueryEclipseLicenseCheckService(t, GROUP, NAME, VERSION, EXPECTED_LICENSE)

	GROUP = "p2.eclipse.plugin"
	NAME = "org.eclipse.ui.win32"
	VERSION = "3.4.400.v20200414-1247"
	EXPECTED_LICENSE = "EPL-2.0"
	innerTestQueryEclipseLicenseCheckService(t, GROUP, NAME, VERSION, EXPECTED_LICENSE)

	GROUP = "p2.eclipse.plugin"
	NAME = "org.eclipse.ui.win32"
	VERSION = "3.4.400"
	EXPECTED_LICENSE = "EPL-2.0"
	innerTestQueryEclipseLicenseCheckService(t, GROUP, NAME, VERSION, EXPECTED_LICENSE)

	GROUP = "p2.eclipse.plugin"
	NAME = "org.apache.ant"
	VERSION = "1.10.12.v20211102-1452"
	EXPECTED_LICENSE = "Apache-2.0 AND EPL-2.0 AND W3C"
	innerTestQueryEclipseLicenseCheckService(t, GROUP, NAME, VERSION, EXPECTED_LICENSE)

	GROUP = "p2.eclipse.plugin"
	NAME = "org.apache.ant"
	VERSION = "1.10.12"
	EXPECTED_LICENSE = "Apache-2.0 AND EPL-2.0 AND W3C"
	innerTestQueryEclipseLicenseCheckService(t, GROUP, NAME, VERSION, EXPECTED_LICENSE)

	GROUP = "p2.eclipse.plugin"
	NAME = "com.google.guava"
	VERSION = "30.1.0.v20210127-2300"
	EXPECTED_LICENSE = "Apache-2.0"
	innerTestQueryEclipseLicenseCheckService(t, GROUP, NAME, VERSION, EXPECTED_LICENSE)

	GROUP = "p2.eclipse.plugin"
	NAME = "com.google.guava"
	VERSION = "30.1.0"
	EXPECTED_LICENSE = "Apache-2.0"
	innerTestQueryEclipseLicenseCheckService(t, GROUP, NAME, VERSION, EXPECTED_LICENSE)

	GROUP = "p2.eclipse.feature"
	NAME = "org.eclipse.jdt"
	VERSION = "3.18.1100"
	EXPECTED_LICENSE = "EPL-2.0"
	innerTestQueryEclipseLicenseCheckService(t, GROUP, NAME, VERSION, EXPECTED_LICENSE)

	GROUP = "p2.p2.installable.unit"
	NAME = "org.eclipse.cdt_root"
	VERSION = "10.6.0.202203091838"
	EXPECTED_LICENSE = "EPL-2.0"
	innerTestQueryEclipseLicenseCheckService(t, GROUP, NAME, VERSION, EXPECTED_LICENSE)

	GROUP = "p2.p2.installable.unit"
	NAME = "org.eclipse.cdt_root"
	VERSION = "10.6.0"
	EXPECTED_LICENSE = "EPL-2.0"
	innerTestQueryEclipseLicenseCheckService(t, GROUP, NAME, VERSION, EXPECTED_LICENSE)
}
