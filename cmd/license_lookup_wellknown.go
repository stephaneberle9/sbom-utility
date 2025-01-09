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

func LookupLicenseForWellknownComponents(cdxComponent schema.CDXComponent) (int, string) {

	// JetBrains components
	if cdxComponent.Group == "com.jetbrains.jdk" {
		if cdxComponent.Name == "jbr_jcef" {
			return schema.LC_TYPE_EXPRESSION, "GPL-2.0-only WITH Classpath-exception-2.0 WITH OpenJDK-assembly-exception-1.0"
		}
	}
	if cdxComponent.Group == "com.jetbrains" {
		if cdxComponent.Name == "mps" {
			return schema.LC_TYPE_ID, "Apache-2.0"
		}
	}

	// MPS extensions components
	if cdxComponent.Group == "com.dslfoundry.javafx" {
		if cdxComponent.Name == "plugin" {
			return schema.LC_TYPE_ID, "Apache-2.0"
		}
	}
	if cdxComponent.Group == "de.itemis.mps" {
		if cdxComponent.Name == "extensions" {
			return schema.LC_TYPE_ID, "Apache-2.0"
		}
	}

	// Modelix components
	if strings.HasPrefix(cdxComponent.Group, "org.modelix") {
		return schema.LC_TYPE_ID, "Apache-2.0"
	}

	// mbedddr components
	if cdxComponent.Group == "com.mbeddr" {
		if cdxComponent.Name == "platform" {
			return schema.LC_TYPE_ID, "EPL-2.0"
		}
	}
	if cdxComponent.Group == "org.mpsqa" {
		if cdxComponent.Name == "all-in-one" {
			return schema.LC_TYPE_ID, "Apache-2.0"
		}
	}

	// itemis components
	if cdxComponent.Group == "de.itemis.mps.rapidfx" {
		if cdxComponent.Name == "core" || cdxComponent.Name == "xdiagram" {
			return schema.LC_TYPE_ID, "Apache-2.0"
		}
	}

	// Yakindu components
	if cdxComponent.Group == "p2.eclipse.plugin" || cdxComponent.Group == "p2.eclipse.feature" || cdxComponent.Group == "p2.p2.installable.unit" || strings.HasPrefix(cdxComponent.Group, "com.itemis") || strings.HasPrefix(cdxComponent.Group, "com.yakindu") || strings.HasPrefix(cdxComponent.Group, "org.yakindu") {
			if strings.HasPrefix(cdxComponent.Name, "com.itemis") || strings.HasPrefix(cdxComponent.Name, "com.yakindu") || strings.HasPrefix(cdxComponent.Name, "org.yakindu") {
					return schema.LC_TYPE_ID, "LicenseRef-itemis-Closed-2.0.2"
			}
	}

	// Third-party components not advertising any license on Maven Central
	if cdxComponent.Group == "org.graphviz" {
		if cdxComponent.Name == "graphviz" {
			// https://graphviz.org/license
			return schema.LC_TYPE_ID, "CPL-1.0"
		}
	}
	if cdxComponent.Group == "trove" {
		if cdxComponent.Name == "trove" {
			if cdxComponent.Version == "1.0.2" {
				// https://github.com/JavaQualitasCorpus/trove-2.1.0
				// https://github.com/palantir/trove
				return schema.LC_TYPE_ID, "LGPL-2.1"
			}
		}
	}

	// Third-party Eclipse components not known/inadequately handled by Eclipse license check serivce
	if cdxComponent.Group == "p2.eclipse.feature" {
		if cdxComponent.Name == "org.eclipse.mylyn_feature" {
			// https://projects.eclipse.org/projects/tools.mylyn
			return schema.LC_TYPE_ID, "EPL-1.0"
		}
	}
	if cdxComponent.Group == "p2.eclipse.plugin" {
		if cdxComponent.Name == "uk.co.spudsoft.birt.emitters.excel" {
			// https://github.com/eclipse-birt/birt/tree/master/engine/uk.co.spudsoft.birt.emitters.excel
			// https://mvnrepository.com/artifact/org.eclipse.birt/uk.co.spudsoft.birt.emitters.excel/4.9.0
			return schema.LC_TYPE_ID, "EPL-2.0"
		}
	}
	if cdxComponent.Group == "p2.eclipse.feature" {
		if cdxComponent.Name == "com.sun.jna.feature" {
			// https://github.com/java-native-access/jna
			return schema.LC_TYPE_EXPRESSION, "Apache-2.0 OR LGPL-2.1-or-later"
		}
	}
	if cdxComponent.Group == "p2.eclipse.plugin" {
		if cdxComponent.Name == "com.sun.el" || cdxComponent.Name == "javax.el" || cdxComponent.Name == "javax.servlet.jsp" {
			if strings.HasPrefix(cdxComponent.Version, "2.2.0") {
				// https://download.eclipse.org/tools/orbit/downloads/drops/R20201118194144/repository/plugins/com.sun.el_2.2.0.v201303151357.jar > about.html
				// https://download.eclipse.org/tools/orbit/downloads/drops/R20201118194144/repository/plugins/javax.el_2.2.0.v201303151357.jar > about.html
				// https://download.eclipse.org/tools/orbit/downloads/drops/R20201118194144/repository/plugins/javax.servlet.jsp_2.2.0.v201112011158.jar > about.html
				return schema.LC_TYPE_EXPRESSION, "EPL-1.0 AND CDDL-1.0"
			}
		}
	}
	if cdxComponent.Group == "p2.eclipse.plugin" {
		if cdxComponent.Name == "org.apache.jasper.glassfish" {
			if strings.HasPrefix(cdxComponent.Version, "2.2.2") {
				// https://download.eclipse.org/tools/orbit/downloads/drops/R20201118194144/repository/plugins/org.apache.jasper.glassfish_2.2.2.v201501141630.jar > about.html
				return schema.LC_TYPE_EXPRESSION, "EPL-1.0 AND Apache-2.0 AND CDDL-1.0"
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
				return schema.LC_TYPE_ID, "Apache-2.0"
			}
		}
	}
	if cdxComponent.Group == "p2.eclipse.plugin" {
		if cdxComponent.Name == "org.w3c.dom.svg.extension" {
			// Same as p2.eclipse.plugin:org.w3c.dom.svg:*
			// https://download.eclipse.org/tools/orbit/downloads/drops/R20201118194144/repository/plugins/org.w3c.dom.svg_1.1.0.v201011041433.jar > about.html
			return schema.LC_TYPE_ID, "Apache-2.0"
		}
	}
	if cdxComponent.Group == "p2.eclipse.plugin" {
		if cdxComponent.Name == "com.opencsv" {
			if strings.HasPrefix(cdxComponent.Version, "3.7.0") {
				// https://opencsv.sourceforge.net/#can_i_use_opencsv_in_my_commercial_applications
				return schema.LC_TYPE_ID, "Apache-2.0"
			}
		}
	}
	if cdxComponent.Group == "p2.eclipse.plugin" {
		if cdxComponent.Name == "org.josql" {
			// https://github.com/bowbahdoe/josql
			return schema.LC_TYPE_ID, "Apache-2.0"
		}
	}
	if cdxComponent.Group == "p2.eclipse.plugin" {
		if cdxComponent.Name == "org.joda.convert" {
			// https://github.com/JodaOrg/joda-convert
			return schema.LC_TYPE_ID, "Apache-2.0"
		}
	}
	if cdxComponent.Group == "p2.eclipse.plugin" {
		if cdxComponent.Name == "org.tukaani.xz" {
			// https://github.com/tukaani-project/xz-java
			return schema.LC_TYPE_ID, "0BSD"
		}
	}
	if cdxComponent.Group == "p2.eclipse.plugin" {
		if cdxComponent.Name == "org.jfree.chart" || cdxComponent.Name == "org.jfree.jcommon" {
			// https://www.jfree.org/jfreechart
			// https://www.jfree.org/jcommon
			return schema.LC_TYPE_ID, "LGPL-3.0"
		}
	}
	if cdxComponent.Group == "p2.eclipse.plugin" {
		if cdxComponent.Name == "jira-rest-java-client-api" || cdxComponent.Name == "jira-rest-java-client-core" {
			if strings.HasPrefix(cdxComponent.Version, "6.1.0") {
				// https://mvnrepository.com/artifact/com.atlassian.jira/jira-rest-java-client-api/6.0.1
				// https://mvnrepository.com/artifact/com.atlassian.jira/jira-rest-java-client-core/6.0.1
				return schema.LC_TYPE_ID, "Apache-2.0"
			}
		}
	}
	if cdxComponent.Group == "p2.eclipse.plugin" || cdxComponent.Group == "p2.eclipse.feature" {
		if strings.HasPrefix(cdxComponent.Name, "me.glindholm.connector.eclipse") {
			// https://github.com/gnl42/JiraConnector
			return schema.LC_TYPE_ID, "EPL-1.0"
		}
	}
	if cdxComponent.Group == "p2.eclipse.plugin" {
		if cdxComponent.Name == "org.jetbrains.kotlin.osgi-bundle" {
			// https://mvnrepository.com/artifact/org.jetbrains.kotlin/kotlin-osgi-bundle/2.0.20
			return schema.LC_TYPE_ID, "Apache-2.0"
		}
	}

	return schema.LC_TYPE_INVALID, ""
}
