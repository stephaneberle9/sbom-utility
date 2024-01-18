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
	"github.com/CycloneDX/sbom-utility/schema"
)

func LookupLicenseForWellknownComponents(cdxComponent schema.CDXComponent) (int, string) {
	if cdxComponent.Group == "com.dslfoundry.javafx" {
		if cdxComponent.Name == "plugin" {
			return schema.LC_TYPE_ID, "Apache-2.0"
		}
	}
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
	if cdxComponent.Group == "com.mbeddr" {
		if cdxComponent.Name == "platform" {
			return schema.LC_TYPE_ID, "EPL-1.0"
		}
	}
	if cdxComponent.Group == "de.itemis.mps.rapidfx" {
		if cdxComponent.Name == "core" || cdxComponent.Name == "xdiagram" {
			return schema.LC_TYPE_ID, "Apache-2.0"
		}
	}
	if cdxComponent.Group == "de.itemis.mps" {
		if cdxComponent.Name == "extensions" {
			return schema.LC_TYPE_ID, "Apache-2.0"
		}
	}
	if cdxComponent.Group == "org.graphviz" {
		if cdxComponent.Name == "graphviz" {
			return schema.LC_TYPE_ID, "CPL-1.0"
		}
	}
	return schema.LC_TYPE_INVALID, ""
}
