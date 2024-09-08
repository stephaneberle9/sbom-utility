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

func innerTestQueryEclipseLicenseCheckService(t *testing.T, group string, name string, version string, expectedLicense string) {
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
	getLogger().Infof("license: `%s`", license)

	if license != expectedLicense {
		t.Errorf("License: expected `%s`, actual `%s`\n",
			expectedLicense, license)
		return
	}
}

// ------------------------------------
// P2 component license detection tests
// ------------------------------------

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

	GROUP = "p2.eclipse.feature"
	NAME = "org.eclipse.jdt"
	VERSION = "3.18.1100.v20220308-0310"
	EXPECTED_LICENSE = "EPL-2.0"
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
