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
	"fmt"

	"github.com/CycloneDX/sbom-utility/schema"
)

type LicenseFinderServiceData struct {
	finders []LicenseFinder
}

var LicenseFinderService *LicenseFinderServiceData = &LicenseFinderServiceData{
	finders: []LicenseFinder{
		MavenComponentLicenseFinder, P2ComponentLicenseFinder, NpmComponentLicenseFinder,
	},
}

func (service *LicenseFinderServiceData) Startup() {
	for _, finder := range service.finders {
		finder.Startup()
	}
}

func (service *LicenseFinderServiceData) Shutdown() {
	for _, finder := range service.finders {
		finder.Shutdown()
	}
}

func (service *LicenseFinderServiceData) IsApplicable(cdxComponent schema.CDXComponent) (bool, error) {
	for _, finder := range service.finders {
		applicable, err := finder.IsApplicable(cdxComponent)
		if err != nil {
			return false, err
		}
		if applicable {
			return true, nil
		}
	}
	return false, nil
}

func (service *LicenseFinderServiceData) FindLicenses(cdxComponent schema.CDXComponent) ([]schema.CDXLicenseChoice, error) {
	for _, finder := range service.finders {
		applicable, err := finder.IsApplicable(cdxComponent)
		if err != nil {
			return nil, err
		}
		if applicable {
			return finder.FindLicenses(cdxComponent)
		}
	}
	return nil, fmt.Errorf("no applicable license finder found for component: %v", cdxComponent)
}
