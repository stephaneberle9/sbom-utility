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

func LookupLicenseUrlForWellknownComponents(cdxComponent schema.CDXComponent) string {	
	if cdxComponent.Group == "com.dslfoundry.javafx" {
		if cdxComponent.Name == "plugin" {
			return "https://www.apache.org/licenses/LICENSE-2.0"
		}
	}
	if cdxComponent.Group == "com.jetbrains.jdk" {
		if cdxComponent.Name == "jbr_jcef" {
			return "https://opensource.org/licenses/GPL-2.0"
		}
	}
	if cdxComponent.Group == "com.jetbrains" {
		if cdxComponent.Name == "mps" {
			return "https://www.apache.org/licenses/LICENSE-2.0"
		}
	}
	if cdxComponent.Group == "com.mbeddr" {
		if cdxComponent.Name == "platform" {
			return "http://www.eclipse.org/legal/epl-v10.html"
		}
	}
	if cdxComponent.Group == "de.itemis.mps.rapidfx" {
		if cdxComponent.Name == "core" || cdxComponent.Name == "xdiagram" {
			return "https://www.apache.org/licenses/LICENSE-2.0"
		}
	}
	if cdxComponent.Group == "de.itemis.mps" {
		if cdxComponent.Name == "extensions" {
			return "https://www.apache.org/licenses/LICENSE-2.0"
		}
	}
	if cdxComponent.Group == "org.graphviz" {
		if cdxComponent.Name == "graphviz" {
			return "https://opensource.org/license/cpl1-0-txt"
		}
	}
	return ""
}
