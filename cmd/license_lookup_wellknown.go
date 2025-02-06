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
	"strings"

	"github.com/CycloneDX/sbom-utility/schema"

)

func LookupLicenseForWellknownComponents(cdxComponent schema.CDXComponent) []schema.CDXLicenseChoice {

	if licenseChoices := lookupLicenseForWellknownMavenComponents(cdxComponent); licenseChoices != nil {
		return licenseChoices
	}

	if licenseChoices := lookupLicenseForWellknownP2Components(cdxComponent); licenseChoices != nil {
		return licenseChoices
	}

	if licenseChoices := lookupLicenseForWellknownNpmComponents(cdxComponent); licenseChoices != nil {
		return licenseChoices
	}

	if licenseChoices := lookupLicenseForWellknownRustComponents(cdxComponent); licenseChoices != nil {
		return licenseChoices
	}

	return nil
}

func lookupLicenseForWellknownMavenComponents(cdxComponent schema.CDXComponent) []schema.CDXLicenseChoice {
	// JetBrains components
	if cdxComponent.Group == "com.jetbrains.jdk" {
		if cdxComponent.Name == "jbr_jcef" {
			return licenseWithExpression("GPL-2.0-only WITH Classpath-exception-2.0 WITH OpenJDK-assembly-exception-1.0")
		}
	}
	if cdxComponent.Group == "com.jetbrains" {
		if cdxComponent.Name == "mps" {
			return licenseWithId("Apache-2.0")
		}
	}

	// MPS extensions components
	if cdxComponent.Group == "com.dslfoundry.javafx" {
		if cdxComponent.Name == "plugin" {
			return licenseWithId("Apache-2.0")
		}
	}
	if cdxComponent.Group == "de.itemis.mps" {
		if cdxComponent.Name == "extensions" {
			return licenseWithId("Apache-2.0")
		}
	}

	// Modelix components
	if strings.HasPrefix(cdxComponent.Group, "org.modelix") {
		return licenseWithId("Apache-2.0")
	}

	// mbedddr components
	if cdxComponent.Group == "com.mbeddr" {
		if cdxComponent.Name == "platform" {
			return licenseWithId("EPL-2.0")
		}
	}
	if cdxComponent.Group == "org.mpsqa" {
		if cdxComponent.Name == "all-in-one" {
			return licenseWithId("Apache-2.0")
		}
	}

	// itemis components
	if cdxComponent.Group == "de.itemis.mps.rapidfx" {
		if cdxComponent.Name == "core" || cdxComponent.Name == "xdiagram" {
			return licenseWithId("Apache-2.0")
		}
	}
	if cdxComponent.Group == "com.itemis.solutions" {
		if cdxComponent.Name == "platform-client-sdk-okhttp" || cdxComponent.Name == "platform-client-sdk-vertx" || cdxComponent.Name == "platform-client-sdk-kotlin-ktor" {
			return licenseWithId("Apache-2.0")
		}
	}

	// Yakindu components
	if strings.HasPrefix(cdxComponent.Group, "com.itemis") || strings.HasPrefix(cdxComponent.Group, "com.yakindu") || strings.HasPrefix(cdxComponent.Group, "org.yakindu") {
			if strings.HasPrefix(cdxComponent.Name, "com.itemis") || strings.HasPrefix(cdxComponent.Name, "com.yakindu") || strings.HasPrefix(cdxComponent.Name, "org.yakindu") {
					return licenseWithId("LicenseRef-itemis-Closed-2.0.2")
			}
	}

	// Third-party components not advertising any license on Maven Central
	if cdxComponent.Group == "org.graphviz" {
		if cdxComponent.Name == "graphviz" {
			// https://graphviz.org/license
			return licenseWithId("CPL-1.0")
		}
	}
	if cdxComponent.Group == "trove" {
		if cdxComponent.Name == "trove" {
			if cdxComponent.Version == "1.0.2" {
				// https://github.com/JavaQualitasCorpus/trove-2.1.0
				// https://github.com/palantir/trove
				return licenseWithId("LGPL-2.1")
			}
		}
	}
	if cdxComponent.Group == "org.jsweet.ext" {
		if cdxComponent.Name == "typescript.java-ts.core" {
			// https://github.com/cincheo/jsweet/blob/develop/typescript.java-ts.core/LICENSE
			return licenseWithId("MIT")
		}
	}

	return nil
}

func lookupLicenseForWellknownP2Components(cdxComponent schema.CDXComponent) []schema.CDXLicenseChoice {
	// Yakindu components
	if cdxComponent.Group == "p2.eclipse.plugin" || cdxComponent.Group == "p2.eclipse.feature" || cdxComponent.Group == "p2.p2.installable.unit" {
		if strings.HasPrefix(cdxComponent.Name, "com.itemis") || strings.HasPrefix(cdxComponent.Name, "com.yakindu") || strings.HasPrefix(cdxComponent.Name, "org.yakindu") {
				return licenseWithId("LicenseRef-itemis-Closed-2.0.2")
		}
	}

	// Third-party Eclipse components not known/inadequately handled by Eclipse license check serivce
	if cdxComponent.Group == "p2.eclipse.feature" {
		if cdxComponent.Name == "org.eclipse.mylyn_feature" {
			// https://projects.eclipse.org/projects/tools.mylyn
			return licenseWithId("EPL-1.0")
		}
	}
	if cdxComponent.Group == "p2.eclipse.plugin" {
		if cdxComponent.Name == "uk.co.spudsoft.birt.emitters.excel" {
			// https://github.com/eclipse-birt/birt/tree/master/engine/uk.co.spudsoft.birt.emitters.excel
			// https://mvnrepository.com/artifact/org.eclipse.birt/uk.co.spudsoft.birt.emitters.excel/4.9.0
			return licenseWithId("EPL-2.0")
		}
	}
	if cdxComponent.Group == "p2.eclipse.feature" {
		if cdxComponent.Name == "com.sun.jna.feature" {
			// https://github.com/java-native-access/jna
			return licenseWithExpression("Apache-2.0 OR LGPL-2.1-or-later")
		}
	}
	if cdxComponent.Group == "p2.eclipse.plugin" {
		if cdxComponent.Name == "com.sun.el" || cdxComponent.Name == "javax.el" || cdxComponent.Name == "javax.servlet.jsp" {
			if strings.HasPrefix(cdxComponent.Version, "2.2.0") {
				// https://download.eclipse.org/tools/orbit/downloads/drops/R20201118194144/repository/plugins/com.sun.el_2.2.0.v201303151357.jar > about.html
				// https://download.eclipse.org/tools/orbit/downloads/drops/R20201118194144/repository/plugins/javax.el_2.2.0.v201303151357.jar > about.html
				// https://download.eclipse.org/tools/orbit/downloads/drops/R20201118194144/repository/plugins/javax.servlet.jsp_2.2.0.v201112011158.jar > about.html
				return licenseWithExpression("EPL-1.0 AND CDDL-1.0")
			}
		}
	}
	if cdxComponent.Group == "p2.eclipse.plugin" {
		if cdxComponent.Name == "org.apache.jasper.glassfish" {
			if strings.HasPrefix(cdxComponent.Version, "2.2.2") {
				// https://download.eclipse.org/tools/orbit/downloads/drops/R20201118194144/repository/plugins/org.apache.jasper.glassfish_2.2.2.v201501141630.jar > about.html
				return licenseWithExpression("EPL-1.0 AND Apache-2.0 AND CDDL-1.0")
			}
		}
	}
	if cdxComponent.Group == "p2.eclipse.plugin" {
		if strings.HasPrefix(cdxComponent.Name, "org.apache.batik.dom") || strings.HasPrefix(cdxComponent.Name, "org.apache.batik.transcoder") {
			if strings.HasPrefix(cdxComponent.Version, "1.14.0") {
				// https://download.eclipse.org/tools/orbit/downloads/drops/R20210825222808
				// https://clearlydefined.io/definitions/maven/mavencentral/org.apache.xmlgraphics/batik-dom/1.14
				// https://clearlydefined.io/definitions/maven/mavencentral/org.apache.xmlgraphics/batik-svg-dom/1.14
				// https://clearlydefined.io/definitions/maven/mavencentral/org.apache.xmlgraphics/batik-transcoder/1.14
				return licenseWithId("Apache-2.0")
			}
		}
	}
	if cdxComponent.Group == "p2.eclipse.plugin" {
		if cdxComponent.Name == "org.w3c.dom.svg.extension" {
			// Same as p2.eclipse.plugin:org.w3c.dom.svg:*
			// https://download.eclipse.org/tools/orbit/downloads/drops/R20201118194144/repository/plugins/org.w3c.dom.svg_1.1.0.v201011041433.jar > about.html
			return licenseWithId("Apache-2.0")
		}
	}
	if cdxComponent.Group == "p2.eclipse.plugin" {
		if cdxComponent.Name == "com.opencsv" {
			if strings.HasPrefix(cdxComponent.Version, "3.7.0") {
				// https://opencsv.sourceforge.net/#can_i_use_opencsv_in_my_commercial_applications
				return licenseWithId("Apache-2.0")
			}
		}
	}
	if cdxComponent.Group == "p2.eclipse.plugin" {
		if cdxComponent.Name == "org.josql" {
			// https://github.com/bowbahdoe/josql
			return licenseWithId("Apache-2.0")
		}
	}
	if cdxComponent.Group == "p2.eclipse.plugin" {
		if cdxComponent.Name == "org.joda.convert" {
			// https://github.com/JodaOrg/joda-convert
			return licenseWithId("Apache-2.0")
		}
	}
	if cdxComponent.Group == "p2.eclipse.plugin" {
		if cdxComponent.Name == "org.tukaani.xz" {
			// https://github.com/tukaani-project/xz-java
			return licenseWithId("0BSD")
		}
	}
	if cdxComponent.Group == "p2.eclipse.plugin" {
		if cdxComponent.Name == "org.jfree.chart" || cdxComponent.Name == "org.jfree.jcommon" {
			// https://www.jfree.org/jfreechart
			// https://www.jfree.org/jcommon
			return licenseWithId("LGPL-3.0")
		}
	}
	if cdxComponent.Group == "p2.eclipse.plugin" {
		if cdxComponent.Name == "jira-rest-java-client-api" || cdxComponent.Name == "jira-rest-java-client-core" {
			if strings.HasPrefix(cdxComponent.Version, "6.1.0") {
				// https://mvnrepository.com/artifact/com.atlassian.jira/jira-rest-java-client-api/6.0.1
				// https://mvnrepository.com/artifact/com.atlassian.jira/jira-rest-java-client-core/6.0.1
				return licenseWithId("Apache-2.0")
			}
		}
	}
	if cdxComponent.Group == "p2.eclipse.plugin" || cdxComponent.Group == "p2.eclipse.feature" {
		if strings.HasPrefix(cdxComponent.Name, "me.glindholm.connector.eclipse") {
			// https://github.com/gnl42/JiraConnector
			return licenseWithId("EPL-1.0")
		}
	}
	if cdxComponent.Group == "p2.eclipse.plugin" {
		if cdxComponent.Name == "org.jetbrains.kotlin.osgi-bundle" {
			// https://mvnrepository.com/artifact/org.jetbrains.kotlin/kotlin-osgi-bundle/2.0.20
			return licenseWithId("Apache-2.0")
		}
	}

	return nil
}

func lookupLicenseForWellknownNpmComponents(cdxComponent schema.CDXComponent) []schema.CDXLicenseChoice {
	// Modelix components
	if cdxComponent.Group == "@modelix" {
		return licenseWithId("Apache-2.0")
	}

	// itemis components
	if cdxComponent.Group == "@itemis-solutions" {
		if cdxComponent.Name == "platform-web-components" {
			return licenseWithId("LicenseRef-itemis-Closed")
		}
	}
	if cdxComponent.Group == "@itemis-solutions" {
		if cdxComponent.Name == "platform-client-sdk" {
			return licenseWithId("Apache-2.0")
		}
	}
	if cdxComponent.Group == "@itemis-secure" {
		if cdxComponent.Name == "calculation" || cdxComponent.Name == "ts-model" {
			return licenseWithId("LicenseRef-itemis-Closed")
		}
	}
	if cdxComponent.Group == "@itemis-secure" {
		if cdxComponent.Name == "repository-client-sdk" {
			return licenseWithId("Apache-2.0")
		}
	}

	// Third-party commercial components
	if cdxComponent.Group == "@clientio" || cdxComponent.Group == ""{
		if cdxComponent.Name == "rappid" {
			// https://www.jointjs.com/license
			return licenseWithId("LicenseRef-client-io-Closed")
		}
	}
	if cdxComponent.Group == "@joint" {
		if cdxComponent.Name == "plus" {
			// https://www.jointjs.com/license
			return licenseWithId("LicenseRef-client-io-Closed")
		}
	}

	// Third-party components not advertising any license in npm registry
	if cdxComponent.Group == "" {
		if cdxComponent.Name == "browser-assert" {
			// https://github.com/socialally/browser-assert/blob/master/LICENSE
			return licenseWithId("MIT")
		}
	}

	return nil
}

func lookupLicenseForWellknownRustComponents(cdxComponent schema.CDXComponent) []schema.CDXLicenseChoice {
	// Third-party Rust components
	if cdxComponent.Group == "" {
		if cdxComponent.Name == "ring" {
			// https://github.com/briansmith/ring?tab=License-1-ov-file#readme
			return licenseWithExpression("OpenSSL AND SSLeay-standalone AND ISC AND MIT")
		}
	}

	return nil
}

func licenseWithId(licenseId string) []schema.CDXLicenseChoice {
	return []schema.CDXLicenseChoice{
		{
			License: &schema.CDXLicense{
				Id: licenseId,
			},
		},
	}
}

func licenseWithExpression(licenseExpression string) []schema.CDXLicenseChoice {
	return []schema.CDXLicenseChoice{
		{
			CDXLicenseExpression: schema.CDXLicenseExpression{
				Expression: licenseExpression,
			},
		},
	}
}