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

func innerTestIsFullyQualifiedMavenComponent(t *testing.T, purl string, expectedResult bool) {
	t.Logf("PURL under test: `%s`", purl)

	var err error
	cdxComponent := schema.CDXComponent{
		Purl:   purl,
	}

	result, err := IsFullyQualifiedMavenComponent(cdxComponent)
	if err != nil {
		t.Errorf("unable to determine if given component is a Maven component: `%v`: `%s`\n", cdxComponent, err.Error())
		return
	}

	if result != expectedResult {
		t.Errorf("Is Maven component: expected `%t`, actual `%t`\n",
		expectedResult, result)
		return
	}
}

func innerTestFindLicensesInPom(t *testing.T, group string, name string, version string, expectedLicense string, expectedLicenseUrl string) {
	t.Logf("Component under test: `%s:%s:%s`", group, name, version)

	var err error
	cdxComponent := schema.CDXComponent{
		Group:   group,
		Name:    name,
		Version: version,
	}

	pomLicenses, err := FindLicensesInPom(cdxComponent)
	if err != nil {
		t.Errorf("unable to find POM of component `%v`: `%s`\n", cdxComponent, err.Error())
		return
	}
	if len(pomLicenses) == 0 {
		t.Errorf("no license found in POM of component `%v`\n", cdxComponent)
		return
	}
	if len(pomLicenses) > 2 {
		t.Errorf("multiple licenses found in POM of component `%v`\n", cdxComponent)
		return
	}
	t.Logf("pomLicenses[0]: `%s`, pomLicenses[1]: `%s`", pomLicenses[0], pomLicenses[1])

	if pomLicenses[0] != expectedLicense {
		t.Errorf("License: expected `%s`, actual `%s`\n",
			expectedLicense, pomLicenses[0])
		return
	}
	if pomLicenses[1] != expectedLicenseUrl {
		t.Errorf("License: expected `%s`, actual `%s`\n",
			expectedLicenseUrl, pomLicenses[1])
		return
	}
}

// ---------------------------------------
// Maven component license detection tests
// ---------------------------------------

func TestIsFullyQualifiedMavenComponent(t *testing.T) {
	PURL := "pkg:maven/org.apache.ant/ant@1.10.6?type=jar"
	innerTestIsFullyQualifiedMavenComponent(t, PURL, true)
	
	PURL = "pkg:maven/org.apache.ant/ant@1.10.6?classifier=lib%2Fant-apache-bcel.jar&type=jar"
	innerTestIsFullyQualifiedMavenComponent(t, PURL, true)

	PURL = "pkg:maven/p2.eclipse.plugin/org.apache.ant@1.10.12.v20211102-1452?type=eclipse-plugin"
	innerTestIsFullyQualifiedMavenComponent(t, PURL, false)

	PURL = "pkg:maven/p2.eclipse.plugin/org.apache.ant@1.10.12.v20211102-1452?classifier=lib%2Fant-apache-bcel.jar&type=eclipse-plugin"
	innerTestIsFullyQualifiedMavenComponent(t, PURL, false)
}

func TestFindLicensesInPom(t *testing.T) {
	GROUP := "ch.qos.reload4j"
	NAME := "reload4j"
	VERSION := "1.2.22"
	EXPECTED_LICENSE := "The Apache Software License, Version 2.0"
	EXPECTED_LICENSE_URL := "http://www.apache.org/licenses/LICENSE-2.0.txt"
	innerTestFindLicensesInPom(t, GROUP, NAME, VERSION, EXPECTED_LICENSE, EXPECTED_LICENSE_URL)

	GROUP = "com.fasterxml.jackson.core"
	NAME = "jackson-annotations"
	VERSION = "2.12.7"
	EXPECTED_LICENSE = "The Apache Software License, Version 2.0"
	EXPECTED_LICENSE_URL = "http://www.apache.org/licenses/LICENSE-2.0.txt"
	innerTestFindLicensesInPom(t, GROUP, NAME, VERSION, EXPECTED_LICENSE, EXPECTED_LICENSE_URL)

	GROUP = "com.fasterxml.jackson.core"
	NAME = "jackson-core"
	VERSION = "2.12.7"
	EXPECTED_LICENSE = "The Apache Software License, Version 2.0"
	EXPECTED_LICENSE_URL = "http://www.apache.org/licenses/LICENSE-2.0.txt"
	innerTestFindLicensesInPom(t, GROUP, NAME, VERSION, EXPECTED_LICENSE, EXPECTED_LICENSE_URL)

	GROUP = "com.fasterxml.jackson.core"
	NAME = "jackson-databind"
	VERSION = "2.12.7.1"
	EXPECTED_LICENSE = "The Apache Software License, Version 2.0"
	EXPECTED_LICENSE_URL = "http://www.apache.org/licenses/LICENSE-2.0.txt"
	innerTestFindLicensesInPom(t, GROUP, NAME, VERSION, EXPECTED_LICENSE, EXPECTED_LICENSE_URL)

	GROUP = "com.fasterxml.jackson"
	NAME = "jackson-bom"
	VERSION = "2.12.7"
	EXPECTED_LICENSE = "Apache License, Version 2.0"
	EXPECTED_LICENSE_URL = "http://www.apache.org/licenses/LICENSE-2.0.txt"
	innerTestFindLicensesInPom(t, GROUP, NAME, VERSION, EXPECTED_LICENSE, EXPECTED_LICENSE_URL)

	GROUP = "com.github.virtuald"
	NAME = "curvesapi"
	VERSION = "1.06"
	EXPECTED_LICENSE = "BSD License"
	EXPECTED_LICENSE_URL = "http://opensource.org/licenses/BSD-3-Clause"
	innerTestFindLicensesInPom(t, GROUP, NAME, VERSION, EXPECTED_LICENSE, EXPECTED_LICENSE_URL)

	GROUP = "com.google.code.gson"
	NAME = "gson"
	VERSION = "2.8.5"
	EXPECTED_LICENSE = "Apache 2.0"
	EXPECTED_LICENSE_URL = "http://www.apache.org/licenses/LICENSE-2.0.txt"
	innerTestFindLicensesInPom(t, GROUP, NAME, VERSION, EXPECTED_LICENSE, EXPECTED_LICENSE_URL)

	GROUP = "commons-codec"
	NAME = "commons-codec"
	VERSION = "1.13"
	EXPECTED_LICENSE = "Apache License, Version 2.0"
	EXPECTED_LICENSE_URL = "https://www.apache.org/licenses/LICENSE-2.0.txt"
	innerTestFindLicensesInPom(t, GROUP, NAME, VERSION, EXPECTED_LICENSE, EXPECTED_LICENSE_URL)

	GROUP = "commons-io"
	NAME = "commons-io"
	VERSION = "2.6"
	EXPECTED_LICENSE = "Apache License, Version 2.0"
	EXPECTED_LICENSE_URL = "https://www.apache.org/licenses/LICENSE-2.0.txt"
	innerTestFindLicensesInPom(t, GROUP, NAME, VERSION, EXPECTED_LICENSE, EXPECTED_LICENSE_URL)

	GROUP = "commons-lang"
	NAME = "commons-lang"
	VERSION = "2.6"
	EXPECTED_LICENSE = "The Apache Software License, Version 2.0"
	EXPECTED_LICENSE_URL = "http://www.apache.org/licenses/LICENSE-2.0.txt"
	innerTestFindLicensesInPom(t, GROUP, NAME, VERSION, EXPECTED_LICENSE, EXPECTED_LICENSE_URL)

	GROUP = "junit"
	NAME = "junit"
	VERSION = "4.13.1"
	EXPECTED_LICENSE = "Eclipse Public License 1.0"
	EXPECTED_LICENSE_URL = "http://www.eclipse.org/legal/epl-v10.html"
	innerTestFindLicensesInPom(t, GROUP, NAME, VERSION, EXPECTED_LICENSE, EXPECTED_LICENSE_URL)

	GROUP = "org.apache.ant"
	NAME = "ant-junit"
	VERSION = "1.9.7"
	EXPECTED_LICENSE = "The Apache Software License, Version 2.0"
	EXPECTED_LICENSE_URL = "http://www.apache.org/licenses/LICENSE-2.0.txt"
	innerTestFindLicensesInPom(t, GROUP, NAME, VERSION, EXPECTED_LICENSE, EXPECTED_LICENSE_URL)

	GROUP = "org.apache.ant"
	NAME = "ant-junit4"
	VERSION = "1.9.7"
	EXPECTED_LICENSE = "The Apache Software License, Version 2.0"
	EXPECTED_LICENSE_URL = "http://www.apache.org/licenses/LICENSE-2.0.txt"
	innerTestFindLicensesInPom(t, GROUP, NAME, VERSION, EXPECTED_LICENSE, EXPECTED_LICENSE_URL)

	GROUP = "org.apache.commons"
	NAME = "commons-collections4"
	VERSION = "4.4"
	EXPECTED_LICENSE = "Apache License, Version 2.0"
	EXPECTED_LICENSE_URL = "https://www.apache.org/licenses/LICENSE-2.0.txt"
	innerTestFindLicensesInPom(t, GROUP, NAME, VERSION, EXPECTED_LICENSE, EXPECTED_LICENSE_URL)

	GROUP = "org.apache.commons"
	NAME = "commons-compress"
	VERSION = "1.19"
	EXPECTED_LICENSE = "Apache License, Version 2.0"
	EXPECTED_LICENSE_URL = "https://www.apache.org/licenses/LICENSE-2.0.txt"
	innerTestFindLicensesInPom(t, GROUP, NAME, VERSION, EXPECTED_LICENSE, EXPECTED_LICENSE_URL)

	GROUP = "org.apache.commons"
	NAME = "commons-lang3"
	VERSION = "3.7"
	EXPECTED_LICENSE = "Apache License, Version 2.0"
	EXPECTED_LICENSE_URL = "https://www.apache.org/licenses/LICENSE-2.0.txt"
	innerTestFindLicensesInPom(t, GROUP, NAME, VERSION, EXPECTED_LICENSE, EXPECTED_LICENSE_URL)

	GROUP = "org.apache.commons"
	NAME = "commons-math3"
	VERSION = "3.6.1"
	EXPECTED_LICENSE = "Apache License, Version 2.0"
	EXPECTED_LICENSE_URL = "http://www.apache.org/licenses/LICENSE-2.0.txt"
	innerTestFindLicensesInPom(t, GROUP, NAME, VERSION, EXPECTED_LICENSE, EXPECTED_LICENSE_URL)

	GROUP = "org.apache.poi"
	NAME = "ooxml-schemas"
	VERSION = "1.4"
	EXPECTED_LICENSE = "The Apache Software License, Version 2.0"
	EXPECTED_LICENSE_URL = "http://www.apache.org/licenses/LICENSE-2.0.txt"
	innerTestFindLicensesInPom(t, GROUP, NAME, VERSION, EXPECTED_LICENSE, EXPECTED_LICENSE_URL)

	GROUP = "org.apache.poi"
	NAME = "poi"
	VERSION = "4.1.1"
	EXPECTED_LICENSE = "Apache License, Version 2.0"
	EXPECTED_LICENSE_URL = "http://www.apache.org/licenses/LICENSE-2.0.txt"
	innerTestFindLicensesInPom(t, GROUP, NAME, VERSION, EXPECTED_LICENSE, EXPECTED_LICENSE_URL)

	GROUP = "org.apache.poi"
	NAME = "poi-ooxml"
	VERSION = "4.1.1"
	EXPECTED_LICENSE = "Apache License, Version 2.0"
	EXPECTED_LICENSE_URL = "http://www.apache.org/licenses/LICENSE-2.0.txt"
	innerTestFindLicensesInPom(t, GROUP, NAME, VERSION, EXPECTED_LICENSE, EXPECTED_LICENSE_URL)

	GROUP = "org.apache.poi"
	NAME = "poi-ooxml-schemas"
	VERSION = "4.1.1"
	EXPECTED_LICENSE = "Apache License, Version 2.0"
	EXPECTED_LICENSE_URL = "http://www.apache.org/licenses/LICENSE-2.0.txt"
	innerTestFindLicensesInPom(t, GROUP, NAME, VERSION, EXPECTED_LICENSE, EXPECTED_LICENSE_URL)

	GROUP = "org.apache.xmlbeans"
	NAME = "xmlbeans"
	VERSION = "3.1.0"
	EXPECTED_LICENSE = "The Apache Software License, Version 2.0"
	EXPECTED_LICENSE_URL = "http://www.apache.org/licenses/LICENSE-2.0.txt"
	innerTestFindLicensesInPom(t, GROUP, NAME, VERSION, EXPECTED_LICENSE, EXPECTED_LICENSE_URL)

	GROUP = "org.eclipse.emf"
	NAME = "org.eclipse.emf.codegen"
	VERSION = "2.21.0"
	EXPECTED_LICENSE = "The Eclipse Public License Version 2.0"
	EXPECTED_LICENSE_URL = "https://www.eclipse.org/legal/epl-v20.html"
	innerTestFindLicensesInPom(t, GROUP, NAME, VERSION, EXPECTED_LICENSE, EXPECTED_LICENSE_URL)

	GROUP = "org.eclipse.emf"
	NAME = "org.eclipse.emf.codegen.ecore"
	VERSION = "2.24.0"
	EXPECTED_LICENSE = "The Eclipse Public License Version 2.0"
	EXPECTED_LICENSE_URL = "https://www.eclipse.org/legal/epl-v20.html"
	innerTestFindLicensesInPom(t, GROUP, NAME, VERSION, EXPECTED_LICENSE, EXPECTED_LICENSE_URL)

	GROUP = "org.eclipse.emf"
	NAME = "org.eclipse.emf.common"
	VERSION = "2.21.0"
	EXPECTED_LICENSE = "The Eclipse Public License Version 2.0"
	EXPECTED_LICENSE_URL = "https://www.eclipse.org/legal/epl-v20.html"
	innerTestFindLicensesInPom(t, GROUP, NAME, VERSION, EXPECTED_LICENSE, EXPECTED_LICENSE_URL)

	GROUP = "org.eclipse.emf"
	NAME = "org.eclipse.emf.converter"
	VERSION = "2.10.0"
	EXPECTED_LICENSE = "The Eclipse Public License Version 1.0"
	EXPECTED_LICENSE_URL = "http://www.eclipse.org/legal/epl-v10.html"
	innerTestFindLicensesInPom(t, GROUP, NAME, VERSION, EXPECTED_LICENSE, EXPECTED_LICENSE_URL)

	GROUP = "org.eclipse.emf"
	NAME = "org.eclipse.emf.ecore"
	VERSION = "2.23.0"
	EXPECTED_LICENSE = "The Eclipse Public License Version 2.0"
	EXPECTED_LICENSE_URL = "https://www.eclipse.org/legal/epl-v20.html"
	innerTestFindLicensesInPom(t, GROUP, NAME, VERSION, EXPECTED_LICENSE, EXPECTED_LICENSE_URL)

	GROUP = "org.eclipse.emf"
	NAME = "org.eclipse.emf.ecore.xmi"
	VERSION = "2.16.0"
	EXPECTED_LICENSE = "The Eclipse Public License Version 2.0"
	EXPECTED_LICENSE_URL = "https://www.eclipse.org/legal/epl-v20.html"
	innerTestFindLicensesInPom(t, GROUP, NAME, VERSION, EXPECTED_LICENSE, EXPECTED_LICENSE_URL)

	GROUP = "org.eclipse.emf"
	NAME = "org.eclipse.xsd"
	VERSION = "2.18.0"
	EXPECTED_LICENSE = "The Eclipse Public License Version 2.0"
	EXPECTED_LICENSE_URL = "https://www.eclipse.org/legal/epl-v20.html"
	innerTestFindLicensesInPom(t, GROUP, NAME, VERSION, EXPECTED_LICENSE, EXPECTED_LICENSE_URL)

	GROUP = "org.eclipse.jdt"
	NAME = "ecj"
	VERSION = "3.36.0"
	EXPECTED_LICENSE = "Eclipse Public License - v 2.0"
	EXPECTED_LICENSE_URL = "https://www.eclipse.org/legal/epl-2.0/"
	innerTestFindLicensesInPom(t, GROUP, NAME, VERSION, EXPECTED_LICENSE, EXPECTED_LICENSE_URL)

	GROUP = "org.eclipse.jdt"
	NAME = "org.eclipse.jdt.core"
	VERSION = "3.36.0"
	EXPECTED_LICENSE = "Eclipse Public License - v 2.0"
	EXPECTED_LICENSE_URL = "https://www.eclipse.org/legal/epl-2.0/"
	innerTestFindLicensesInPom(t, GROUP, NAME, VERSION, EXPECTED_LICENSE, EXPECTED_LICENSE_URL)

	GROUP = "org.eclipse.jdt"
	NAME = "org.eclipse.jdt.debug"
	VERSION = "3.21.200"
	EXPECTED_LICENSE = "Eclipse Public License - v 2.0"
	EXPECTED_LICENSE_URL = "https://www.eclipse.org/legal/epl-2.0/"
	innerTestFindLicensesInPom(t, GROUP, NAME, VERSION, EXPECTED_LICENSE, EXPECTED_LICENSE_URL)

	GROUP = "org.eclipse.jdt"
	NAME = "org.eclipse.jdt.launching"
	VERSION = "3.21.0"
	EXPECTED_LICENSE = "Eclipse Public License - v 2.0"
	EXPECTED_LICENSE_URL = "https://www.eclipse.org/legal/epl-2.0/"
	innerTestFindLicensesInPom(t, GROUP, NAME, VERSION, EXPECTED_LICENSE, EXPECTED_LICENSE_URL)

	GROUP = "org.eclipse.platform"
	NAME = "org.eclipse.core.commands"
	VERSION = "3.11.100"
	EXPECTED_LICENSE = "Eclipse Public License - v 2.0"
	EXPECTED_LICENSE_URL = "https://www.eclipse.org/legal/epl-2.0/"
	innerTestFindLicensesInPom(t, GROUP, NAME, VERSION, EXPECTED_LICENSE, EXPECTED_LICENSE_URL)

	GROUP = "org.eclipse.platform"
	NAME = "org.eclipse.core.contenttype"
	VERSION = "3.7.800"
	EXPECTED_LICENSE = "Eclipse Public License - v 2.0"
	EXPECTED_LICENSE_URL = "https://www.eclipse.org/legal/epl-2.0/"
	innerTestFindLicensesInPom(t, GROUP, NAME, VERSION, EXPECTED_LICENSE, EXPECTED_LICENSE_URL)

	GROUP = "org.eclipse.platform"
	NAME = "org.eclipse.core.expressions"
	VERSION = "3.9.200"
	EXPECTED_LICENSE = "Eclipse Public License - v 2.0"
	EXPECTED_LICENSE_URL = "https://www.eclipse.org/legal/epl-2.0/"
	innerTestFindLicensesInPom(t, GROUP, NAME, VERSION, EXPECTED_LICENSE, EXPECTED_LICENSE_URL)

	GROUP = "org.eclipse.platform"
	NAME = "org.eclipse.core.filesystem"
	VERSION = "1.10.200"
	EXPECTED_LICENSE = "Eclipse Public License - v 2.0"
	EXPECTED_LICENSE_URL = "https://www.eclipse.org/legal/epl-2.0/"
	innerTestFindLicensesInPom(t, GROUP, NAME, VERSION, EXPECTED_LICENSE, EXPECTED_LICENSE_URL)

	GROUP = "org.eclipse.platform"
	NAME = "org.eclipse.core.jobs"
	VERSION = "3.10.800"
	EXPECTED_LICENSE = "Eclipse Public License - v 2.0"
	EXPECTED_LICENSE_URL = "https://www.eclipse.org/legal/epl-2.0/"
	innerTestFindLicensesInPom(t, GROUP, NAME, VERSION, EXPECTED_LICENSE, EXPECTED_LICENSE_URL)

	GROUP = "org.eclipse.platform"
	NAME = "org.eclipse.core.resources"
	VERSION = "3.20.0"
	EXPECTED_LICENSE = "Eclipse Public License - v 2.0"
	EXPECTED_LICENSE_URL = "https://www.eclipse.org/legal/epl-2.0/"
	innerTestFindLicensesInPom(t, GROUP, NAME, VERSION, EXPECTED_LICENSE, EXPECTED_LICENSE_URL)

	GROUP = "org.eclipse.platform"
	NAME = "org.eclipse.core.runtime"
	VERSION = "3.19.0"
	EXPECTED_LICENSE = "Eclipse Public License - v 2.0"
	EXPECTED_LICENSE_URL = "https://www.eclipse.org/legal/epl-2.0/"
	innerTestFindLicensesInPom(t, GROUP, NAME, VERSION, EXPECTED_LICENSE, EXPECTED_LICENSE_URL)

	GROUP = "org.eclipse.platform"
	NAME = "org.eclipse.core.variables"
	VERSION = "3.6.200"
	EXPECTED_LICENSE = "Eclipse Public License - v 2.0"
	EXPECTED_LICENSE_URL = "https://www.eclipse.org/legal/epl-2.0/"
	innerTestFindLicensesInPom(t, GROUP, NAME, VERSION, EXPECTED_LICENSE, EXPECTED_LICENSE_URL)

	GROUP = "org.eclipse.platform"
	NAME = "org.eclipse.debug.core"
	VERSION = "3.21.200"
	EXPECTED_LICENSE = "Eclipse Public License - v 2.0"
	EXPECTED_LICENSE_URL = "https://www.eclipse.org/legal/epl-2.0/"
	innerTestFindLicensesInPom(t, GROUP, NAME, VERSION, EXPECTED_LICENSE, EXPECTED_LICENSE_URL)

	GROUP = "org.eclipse.platform"
	NAME = "org.eclipse.equinox.app"
	VERSION = "1.6.400"
	EXPECTED_LICENSE = "Eclipse Public License - v 2.0"
	EXPECTED_LICENSE_URL = "https://www.eclipse.org/legal/epl-2.0/"
	innerTestFindLicensesInPom(t, GROUP, NAME, VERSION, EXPECTED_LICENSE, EXPECTED_LICENSE_URL)

	GROUP = "org.eclipse.platform"
	NAME = "org.eclipse.equinox.common"
	VERSION = "3.18.200"
	EXPECTED_LICENSE = "Eclipse Public License - v 2.0"
	EXPECTED_LICENSE_URL = "https://www.eclipse.org/legal/epl-2.0/"
	innerTestFindLicensesInPom(t, GROUP, NAME, VERSION, EXPECTED_LICENSE, EXPECTED_LICENSE_URL)

	GROUP = "org.eclipse.platform"
	NAME = "org.eclipse.equinox.preferences"
	VERSION = "3.9.100"
	EXPECTED_LICENSE = "Eclipse Public License - v 2.0"
	EXPECTED_LICENSE_URL = "https://www.eclipse.org/legal/epl-2.0/"
	innerTestFindLicensesInPom(t, GROUP, NAME, VERSION, EXPECTED_LICENSE, EXPECTED_LICENSE_URL)

	GROUP = "org.eclipse.platform"
	NAME = "org.eclipse.equinox.registry"
	VERSION = "3.11.400"
	EXPECTED_LICENSE = "Eclipse Public License - v 2.0"
	EXPECTED_LICENSE_URL = "https://www.eclipse.org/legal/epl-2.0/"
	innerTestFindLicensesInPom(t, GROUP, NAME, VERSION, EXPECTED_LICENSE, EXPECTED_LICENSE_URL)

	GROUP = "org.eclipse.platform"
	NAME = "org.eclipse.osgi"
	VERSION = "3.18.600"
	EXPECTED_LICENSE = "Eclipse Public License - v 2.0"
	EXPECTED_LICENSE_URL = "https://www.eclipse.org/legal/epl-2.0/"
	innerTestFindLicensesInPom(t, GROUP, NAME, VERSION, EXPECTED_LICENSE, EXPECTED_LICENSE_URL)

	GROUP = "org.eclipse.platform"
	NAME = "org.eclipse.text"
	VERSION = "3.13.100"
	EXPECTED_LICENSE = "Eclipse Public License - v 2.0"
	EXPECTED_LICENSE_URL = "https://www.eclipse.org/legal/epl-2.0/"
	innerTestFindLicensesInPom(t, GROUP, NAME, VERSION, EXPECTED_LICENSE, EXPECTED_LICENSE_URL)

	GROUP = "org.hamcrest"
	NAME = "hamcrest-core"
	VERSION = "1.3"
	EXPECTED_LICENSE = "New BSD License"
	EXPECTED_LICENSE_URL = "http://www.opensource.org/licenses/bsd-license.php"
	innerTestFindLicensesInPom(t, GROUP, NAME, VERSION, EXPECTED_LICENSE, EXPECTED_LICENSE_URL)

	GROUP = "org.jodconverter"
	NAME = "jodconverter-core"
	VERSION = "4.2.2"
	EXPECTED_LICENSE = "The Apache License, Version 2.0"
	EXPECTED_LICENSE_URL = "http://www.apache.org/licenses/LICENSE-2.0.txt"
	innerTestFindLicensesInPom(t, GROUP, NAME, VERSION, EXPECTED_LICENSE, EXPECTED_LICENSE_URL)

	GROUP = "org.jodconverter"
	NAME = "jodconverter-local"
	VERSION = "4.2.2"
	EXPECTED_LICENSE = "The Apache License, Version 2.0"
	EXPECTED_LICENSE_URL = "http://www.apache.org/licenses/LICENSE-2.0.txt"
	innerTestFindLicensesInPom(t, GROUP, NAME, VERSION, EXPECTED_LICENSE, EXPECTED_LICENSE_URL)

	GROUP = "org.openoffice"
	NAME = "juh"
	VERSION = "4.1.2"
	EXPECTED_LICENSE = "The Apache License, Version 2.0"
	EXPECTED_LICENSE_URL = "http://www.apache.org/licenses/LICENSE-2.0.txt"
	innerTestFindLicensesInPom(t, GROUP, NAME, VERSION, EXPECTED_LICENSE, EXPECTED_LICENSE_URL)

	GROUP = "org.openoffice"
	NAME = "jurt"
	VERSION = "4.1.2"
	EXPECTED_LICENSE = "The Apache License, Version 2.0"
	EXPECTED_LICENSE_URL = "http://www.apache.org/licenses/LICENSE-2.0.txt"
	innerTestFindLicensesInPom(t, GROUP, NAME, VERSION, EXPECTED_LICENSE, EXPECTED_LICENSE_URL)

	GROUP = "org.openoffice"
	NAME = "ridl"
	VERSION = "4.1.2"
	EXPECTED_LICENSE = "The Apache License, Version 2.0"
	EXPECTED_LICENSE_URL = "http://www.apache.org/licenses/LICENSE-2.0.txt"
	innerTestFindLicensesInPom(t, GROUP, NAME, VERSION, EXPECTED_LICENSE, EXPECTED_LICENSE_URL)

	GROUP = "org.openoffice"
	NAME = "unoil"
	VERSION = "4.1.2"
	EXPECTED_LICENSE = "The Apache License, Version 2.0"
	EXPECTED_LICENSE_URL = "http://www.apache.org/licenses/LICENSE-2.0.txt"
	innerTestFindLicensesInPom(t, GROUP, NAME, VERSION, EXPECTED_LICENSE, EXPECTED_LICENSE_URL)

	GROUP = "org.slf4j"
	NAME = "slf4j-api"
	VERSION = "1.7.25"
	EXPECTED_LICENSE = "MIT License"
	EXPECTED_LICENSE_URL = "http://www.opensource.org/licenses/mit-license.php"
	innerTestFindLicensesInPom(t, GROUP, NAME, VERSION, EXPECTED_LICENSE, EXPECTED_LICENSE_URL)
}
