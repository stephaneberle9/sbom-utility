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
	"bufio"
	"bytes"
	"io/fs"
	"reflect"
	"testing"

	"github.com/CycloneDX/sbom-utility/common"
	"github.com/CycloneDX/sbom-utility/schema"
	"github.com/CycloneDX/sbom-utility/utils"

)

const (
	// Test "license list" command
	TEST_LICENSE_LIST_CDX_1_3            = "test/cyclonedx/cdx-1-3-license-list.json"
	TEST_LICENSE_LIST_CDX_1_3_NONE_FOUND = "test/cyclonedx/cdx-1-3-license-list-none-found.json"
	TEST_LICENSE_LIST_CDX_1_4_NONE_FOUND = "test/cyclonedx/cdx-1-4-license-list-none-found.json"

	TEST_LICENSE_LIST_TEXT_CDX_1_4_INVALID_LICENSE_ID    = "test/cyclonedx/cdx-1-4-license-policy-invalid-spdx-id.json"
	TEST_LICENSE_LIST_TEXT_CDX_1_4_INVALID_LICENSE_NAME  = "test/cyclonedx/cdx-1-4-license-policy-invalid-license-name.json"
	TEST_LICENSE_LIST_CDX_1_4_LICENSE_EXPRESSION_IN_NAME = "test/cyclonedx/cdx-1-4-license-expression-in-name.json"
)

// default ResourceTestInfo struct values
const (
	LTI_DEFAULT_LINE_COUNT = -1
)

type LicenseTestInfo struct {
	CommonTestInfo
	ListLineWrap bool
	PolicyFile   string // Note: if not filled in, uses default file: DEFAULT_LICENSE_POLICIES
}

func (ti *LicenseTestInfo) String() string {
	buffer, _ := utils.EncodeAnyToDefaultIndentedJSONStr(ti)
	return buffer.String()
}

func NewLicenseTestInfo(inputFile string, listFormat string, listSummary bool) *LicenseTestInfo {
	var ti = new(LicenseTestInfo)
	var pCommon = &ti.CommonTestInfo
	pCommon.InitBasic(inputFile, listFormat, nil)
	ti.ListSummary = listSummary
	return ti
}

// -------------------------------------------
// license test helper functions
// -------------------------------------------

func innerTestLicenseListBuffered(t *testing.T, testInfo *LicenseTestInfo, whereFilters []common.WhereFilter) (outputBuffer bytes.Buffer, err error) {
	// Declare an output outputBuffer/outputWriter to use used during tests
	var outputWriter = bufio.NewWriter(&outputBuffer)
	// MUST ensure all data is written to buffer before further validation
	defer outputWriter.Flush()

	// Use a test input SBOM formatted in SPDX
	utils.GlobalFlags.PersistentFlags.InputFile = testInfo.InputFile
	utils.GlobalFlags.PersistentFlags.OutputFormat = testInfo.OutputFormat
	utils.GlobalFlags.PersistentFlags.OutputFile = testInfo.OutputFile
	utils.GlobalFlags.PersistentFlags.OutputIndent = testInfo.OutputIndent
	utils.GlobalFlags.LicenseFlags.Summary = testInfo.ListSummary

	// set license policy config. per-test
	var policyConfig *schema.LicensePolicyConfig = LicensePolicyConfig
	if testInfo.PolicyFile != "" && testInfo.PolicyFile != DEFAULT_LICENSE_POLICY_CONFIG {
		policyConfig = new(schema.LicensePolicyConfig)
		err = policyConfig.LoadHashPolicyConfigurationFile(testInfo.PolicyFile, "")
		if err != nil {
			t.Errorf("unable to load policy configuration file: %v", err.Error())
			return
		}
	}

	// Invoke the actual List command (API)
	err = ListLicenses(outputWriter, policyConfig, utils.GlobalFlags.PersistentFlags, utils.GlobalFlags.LicenseFlags, whereFilters)

	return
}

func innerTestLicenseList(t *testing.T, testInfo *LicenseTestInfo) (outputBuffer bytes.Buffer) {

	// Parse out --where filters and exit out if error detected
	whereFilters, err := prepareWhereFilters(t, &testInfo.CommonTestInfo)
	if err != nil {
		return
	}

	// Perform the test with buffered output
	outputBuffer, err = innerTestLicenseListBuffered(t, testInfo, whereFilters)

	// Run all common tests against "result" values in the CommonTestInfo struct
	innerRunReportResultTests(t, &testInfo.CommonTestInfo, outputBuffer, err)

	return
}

func innerTestLicenseExpressionParsing(t *testing.T, expression string, expectedPolicy string) (parsedExpression *schema.CompoundExpression) {
	var err error
	parsedExpression, err = schema.ParseExpression(LicensePolicyConfig, expression)
	if err != nil {
		t.Errorf("unable to parse expression `%s`: `%s`\n", expression, err.Error())
		return
	}

	t.Logf("parsed expression:\n%v", parsedExpression)
	if parsedExpression.CompoundUsagePolicy != expectedPolicy {
		t.Errorf("License Expression: expected `%s`, actual `%s`\n",
			expectedPolicy, parsedExpression.CompoundUsagePolicy)
		return
	}
	return
}

func innerTestLicenseInfoHashing(t *testing.T, licenseName string, licenseUrl string, expectedLicense string, expectedLicenseUrls string, expectedUsagePolicy string) {
	bom := schema.NewBOM("dummyBomFile")
	licenseInfo := schema.LicenseInfo{
		LicenseChoice: schema.CDXLicenseChoice{
			License: &schema.CDXLicense{
				Name: licenseName,
				Url:  licenseUrl,
			},
		},
	}
	err := hashLicenseInfoByLicenseType(bom, LicensePolicyConfig, licenseInfo, make([]common.WhereFilter, 0))
	if err != nil {
		t.Errorf("unable to hash license info `%v`: `%s`\n", licenseInfo, err.Error())
		return
	}

	var licenseInfoKey string
	if licenseName != "" {
		licenseInfoKey = licenseName
	} else {
		licenseInfoKey = licenseUrl
	}
	licenseInfos, ok := bom.LicenseMap.Get(licenseInfoKey)
	if !ok || len(licenseInfos) != 1 {
		t.Errorf("License info count: lookup key `%s`, expected `%d`, actual `%d`\n",
			licenseInfoKey, 1, len(licenseInfos))
		return
	}
	licenseInfo, ok = licenseInfos[0].(schema.LicenseInfo)
	if !ok {
		t.Errorf("License info type: lookup key `%s`, expected `%s`, actual `%s`\n",
			licenseInfoKey, "schema.LicenseInfo", reflect.TypeOf(licenseInfos[0]))
		return
	}

	if licenseInfo.License != expectedLicense {
		t.Errorf("License: expected `%s`, actual `%s`\n",
			expectedLicense, licenseInfo.License)
		return
	}
	if licenseInfo.LicenseUrls != expectedLicenseUrls {
		t.Errorf("License URL(s): expected `%s`, actual `%s`\n",
			expectedLicenseUrls, licenseInfo.LicenseUrls)
		return
	}
	if licenseInfo.UsagePolicy != expectedUsagePolicy {
		t.Errorf("License usage policy: expected `%s`, actual `%s`\n",
			expectedUsagePolicy, licenseInfo.UsagePolicy)
		return
	}
	return
}

// ----------------------------------------
// Command flag tests
// ----------------------------------------

func TestLicenseListInvalidInputFileLoad(t *testing.T) {
	lti := NewLicenseTestInfo(TEST_INPUT_FILE_NON_EXISTENT, FORMAT_DEFAULT, false)
	lti.ResultExpectedError = &fs.PathError{}
	innerTestLicenseList(t, lti)
}

// -------------------------------------------
// Test format unsupported (SPDX)
// -------------------------------------------
func TestLicenseListFormatUnsupportedSPDX1(t *testing.T) {
	lti := NewLicenseTestInfo(TEST_SPDX_2_2_MIN_REQUIRED, FORMAT_DEFAULT, false)
	lti.ResultExpectedError = &schema.UnsupportedFormatError{}
	innerTestLicenseList(t, lti)
}

func TestLicenseListFormatUnsupportedSPDX2(t *testing.T) {
	lti := NewLicenseTestInfo(TEST_SPDX_2_2_EXAMPLE_1, FORMAT_DEFAULT, false)
	lti.ResultExpectedError = &schema.UnsupportedFormatError{}
	innerTestLicenseList(t, lti)
}

//---------------------------
// Raw output tests
//---------------------------

// Verify "license list" command finds all licenses regardless of where they
// are declared in schema (e.g., metadata.component, components list, service list, etc.)
// Note: this includes licenses in ANY hierarchical nesting of components as well.
func TestLicenseListCdx13JsonNoneFound(t *testing.T) {
	// Test CDX 1.3 document
	lti := NewLicenseTestInfo(TEST_LICENSE_LIST_CDX_1_3_NONE_FOUND, FORMAT_JSON, false)
	lti.ResultExpectedLineCount = 1 // null (valid json)
	innerTestLicenseList(t, lti)
}
func TestLicenseListCdx14JsonNoneFound(t *testing.T) {
	lti := NewLicenseTestInfo(TEST_LICENSE_LIST_CDX_1_4_NONE_FOUND, FORMAT_JSON, false)
	lti.ResultExpectedLineCount = 1 // null (valid json)
	innerTestLicenseList(t, lti)
}

func TestLicenseListCdx13CsvNoneFound(t *testing.T) {
	// Test CDX 1.3 document
	lti := NewLicenseTestInfo(TEST_LICENSE_LIST_CDX_1_3_NONE_FOUND, FORMAT_CSV, false)
	lti.ResultExpectedLineCount = 1 // title only
	innerTestLicenseList(t, lti)
}

func TestLicenseListCdx14CsvNoneFound(t *testing.T) {
	// Test CDX 1.4 document
	lti := NewLicenseTestInfo(TEST_LICENSE_LIST_CDX_1_4_NONE_FOUND, FORMAT_CSV, false)
	lti.ResultExpectedLineCount = 1 // title only
	innerTestLicenseList(t, lti)
}

func TestLicenseListCdx13MarkdownNoneFound(t *testing.T) {
	// Test CDX 1.3 document
	lti := NewLicenseTestInfo(TEST_LICENSE_LIST_CDX_1_3_NONE_FOUND, FORMAT_MARKDOWN, false)
	lti.ResultExpectedLineCount = 2 // title and separator rows
	innerTestLicenseList(t, lti)
}

func TestLicenseListCdx14MarkdownNoneFound(t *testing.T) {
	// Test CDX 1.4 document
	lti := NewLicenseTestInfo(TEST_LICENSE_LIST_CDX_1_4_NONE_FOUND, FORMAT_MARKDOWN, false)
	lti.ResultExpectedLineCount = 2 // title and separator rows
	innerTestLicenseList(t, lti)
}

func TestLicenseListCdx13Json(t *testing.T) {
	lti := NewLicenseTestInfo(TEST_LICENSE_LIST_CDX_1_3, FORMAT_JSON, false)
	lti.ResultExpectedLineCount = 92 // array of LicenseChoice JSON objects
	lti.OutputIndent = 6
	buffer := innerTestLicenseList(t, lti)

	numLines, lines := getBufferLinesAndCount(buffer)

	// if numLines != cti.ResultExpectedLineCount {
	// 	t.Errorf("invalid test result: expected: `%v` lines, actual: `%v", cti.ResultExpectedLineCount, numLines)
	// }
	if numLines > lti.ResultExpectedIndentAtLineNum {
		line := lines[lti.ResultExpectedIndentAtLineNum]
		if spaceCount := numberOfLeadingSpaces(line); spaceCount != lti.ResultExpectedIndentLength {
			t.Errorf("invalid test result: expected indent:`%v`, actual: `%v", lti.ResultExpectedIndentLength, spaceCount)
		}
	}
}

//---------------------------
// Summary flag tests
//---------------------------

// Assure listing (report) works with summary flag (i.e., format: "txt")
func TestLicenseListSummaryCdx13Text(t *testing.T) {
	lti := NewLicenseTestInfo(TEST_LICENSE_LIST_CDX_1_3, FORMAT_TEXT, true)
	lti.ResultExpectedLineCount = 20 // title, separator and data rows
	innerTestLicenseList(t, lti)
}

func TestLicenseListSummaryCdx13Markdown(t *testing.T) {
	lti := NewLicenseTestInfo(TEST_LICENSE_LIST_CDX_1_3, FORMAT_MARKDOWN, true)
	lti.ResultExpectedLineCount = 20 // title, separator and data rows
	innerTestLicenseList(t, lti)
}

func TestLicenseListSummaryCdx13Csv(t *testing.T) {
	lti := NewLicenseTestInfo(TEST_LICENSE_LIST_CDX_1_3, FORMAT_CSV, true)
	lti.ResultExpectedLineCount = 19 // title and data rows
	innerTestLicenseList(t, lti)
}

func TestLicenseListTextSummaryCdx14ContainsUndefined(t *testing.T) {
	lti := NewLicenseTestInfo(TEST_LICENSE_LIST_CDX_1_4_NONE_FOUND, FORMAT_DEFAULT, true)
	lti.ResultExpectedLineCount = 4 // 2 title, 2 with UNDEFINED
	lti.ResultLineContainsValues = []string{schema.POLICY_UNDEFINED, LICENSE_NO_ASSERTION, "package-lock.json"}
	lti.ResultLineContainsValuesAtLineNum = 3
	innerTestLicenseList(t, lti)
}

func TestLicenseListPolicyCdx14InvalidLicenseId(t *testing.T) {
	TEST_LICENSE_ID_OR_NAME := "foo"
	lti := NewLicenseTestInfo(TEST_LICENSE_LIST_TEXT_CDX_1_4_INVALID_LICENSE_ID, FORMAT_TEXT, true)
	lti.ResultLineContainsValues = []string{schema.POLICY_UNDEFINED, TEST_LICENSE_ID_OR_NAME}
	lti.ResultLineContainsValuesAtLineNum = 3
	innerTestLicenseList(t, lti)
}

func TestLicenseListPolicyCdx14InvalidLicenseName(t *testing.T) {
	TEST_LICENSE_ID_OR_NAME := "bar"
	lti := NewLicenseTestInfo(TEST_LICENSE_LIST_TEXT_CDX_1_4_INVALID_LICENSE_NAME, FORMAT_TEXT, true)
	lti.ResultLineContainsValues = []string{schema.POLICY_UNDEFINED, TEST_LICENSE_ID_OR_NAME}
	lti.ResultLineContainsValuesAtLineNum = 3
	innerTestLicenseList(t, lti)
}

// ---------------------------
// Where filter tests
// ---------------------------
func TestLicenseListSummaryTextCdx13WhereUsageNeedsReview(t *testing.T) {
	lti := NewLicenseTestInfo(TEST_LICENSE_LIST_CDX_1_3, FORMAT_TEXT, true)
	lti.WhereClause = "usage-policy=needs-review"
	lti.ResultExpectedLineCount = 3 // title and data rows
	innerTestLicenseList(t, lti)
}

func TestLicenseListSummaryTextCdx13WhereUsageUndefined(t *testing.T) {
	lti := NewLicenseTestInfo(TEST_LICENSE_LIST_CDX_1_3, FORMAT_TEXT, true)
	lti.WhereClause = "usage-policy=UNDEFINED"
	lti.ResultExpectedLineCount = 10 // title and data rows
	innerTestLicenseList(t, lti)
}

func TestLicenseListSummaryTextCdx13WhereLicenseTypeName(t *testing.T) {
	lti := NewLicenseTestInfo(TEST_LICENSE_LIST_CDX_1_3, FORMAT_TEXT, true)
	lti.WhereClause = "license-type=name"
	lti.ResultExpectedLineCount = 8 // title and data rows
	innerTestLicenseList(t, lti)
}

func TestLicenseListSummaryTextCdx14LicenseExpInName(t *testing.T) {
	TEST_LICENSE_HUMAN_READABLE_EXPRESSION := "BSD 3-Clause \"New\" or \"Revised\" License OR MIT License"
	TEST_LICENSE_URLS := "https://opensource.org/licenses/BSD-3-Clause, https://opensource.org/licenses/MIT"

	lti := NewLicenseTestInfo(
		TEST_LICENSE_LIST_CDX_1_4_LICENSE_EXPRESSION_IN_NAME,
		FORMAT_TEXT, true)
	lti.WhereClause = "license-type=expression"
	lti.ResultLineContainsValues = []string{schema.POLICY_ALLOW, TEST_LICENSE_HUMAN_READABLE_EXPRESSION, TEST_LICENSE_URLS}
	lti.ResultLineContainsValuesAtLineNum = 3
	lti.ResultExpectedLineCount = 4 // title and data rows
	innerTestLicenseList(t, lti)
}

// Test custom marshal of CDXLicense (empty CDXAttachment)
func TestLicenseListCdx13JsonEmptyAttachment(t *testing.T) {
	lti := NewLicenseTestInfo(
		"test/cyclonedx/cdx-1-3-license-list-no-attachment.json",
		FORMAT_JSON,
		false)
	lti.ResultExpectedLineCount = 36
	lti.ResultLineContainsValues = []string{"\"content\": \"CiAgICAgICAgICAgICA...\""}
	lti.ResultLineContainsValuesAtLineNum = -1 // JSON Hashmaps in Go are not ordered, match any line
	innerTestLicenseList(t, lti)
}

// Tests for expression parser
func TestLicenseExpressionParsingTestComplex1(t *testing.T) {
	SPDX_LICENSE_EXPRESSION_TEST1 := "Apache-2.0 AND (MIT OR GPL-2.0-only)"
	EXPECTED_POLICY := schema.POLICY_ALLOW
	result := innerTestLicenseExpressionParsing(t, SPDX_LICENSE_EXPRESSION_TEST1, EXPECTED_POLICY)
	if result.LeftUsagePolicy != schema.POLICY_ALLOW && result.RightUsagePolicy != schema.POLICY_ALLOW {
		t.Errorf("License Expression: expectedLeft `%s`, actualLeft `%s`, expectedRight `%s`, actualRight `%s`\n",
			schema.POLICY_ALLOW, result.LeftUsagePolicy, schema.POLICY_ALLOW, result.RightUsagePolicy)
	}
}

func TestLicenseExpressionParsingTestComplex2(t *testing.T) {
	SPDX_LICENSE_EXPRESSION_TEST1 := "MPL-1.0 AND (MIT AND AGPL-3.0)"
	EXPECTED_POLICY := schema.POLICY_NEEDS_REVIEW
	result := innerTestLicenseExpressionParsing(t, SPDX_LICENSE_EXPRESSION_TEST1, EXPECTED_POLICY)
	if result.LeftUsagePolicy != schema.POLICY_ALLOW && result.RightUsagePolicy != schema.POLICY_ALLOW {
		t.Errorf("License Expression: expectedLeft `%s`, actualLeft `%s`, expectedRight `%s`, actualRight `%s`\n",
			schema.POLICY_ALLOW, result.LeftUsagePolicy, schema.POLICY_ALLOW, result.RightUsagePolicy)
	}
}

func TestLicenseExpressionParsingCompoundRightSide(t *testing.T) {
	EXP := "Apache-2.0 AND (MIT OR GPL-2.0-only )"
	EXPECTED_POLICY := schema.POLICY_ALLOW
	innerTestLicenseExpressionParsing(t, EXP, EXPECTED_POLICY)
}

func TestLicenseExpressionCompoundLeftSide(t *testing.T) {
	EXP := "(Apache-1.0 OR Apache-1.1 ) AND 0BSD"
	EXPECTED_POLICY := schema.POLICY_ALLOW
	innerTestLicenseExpressionParsing(t, EXP, EXPECTED_POLICY)
}

// Test license expression entirely inside a logical group (i.e., outer parens)
func TestLicenseExpressionSingleCompoundAllow(t *testing.T) {
	EXP := "(MIT OR CC0-1.0)"
	EXPECTED_POLICY := schema.POLICY_ALLOW
	innerTestLicenseExpressionParsing(t, EXP, EXPECTED_POLICY)
}

func TestLicenseExpressionSingleCompoundUndefinedBoth(t *testing.T) {
	EXP := "(FOO OR BAR)"
	EXPECTED_POLICY := schema.POLICY_UNDEFINED
	innerTestLicenseExpressionParsing(t, EXP, EXPECTED_POLICY)
}

func TestLicenseExpressionSingleCompoundUndefinedLeft(t *testing.T) {
	EXP := "(FOO OR MIT)"
	EXPECTED_POLICY := schema.POLICY_ALLOW
	innerTestLicenseExpressionParsing(t, EXP, EXPECTED_POLICY)
}

func TestLicenseExpressionSingleCompoundUndefinedRight(t *testing.T) {
	EXP := "(MIT OR BAR)"
	EXPECTED_POLICY := schema.POLICY_ALLOW
	innerTestLicenseExpressionParsing(t, EXP, EXPECTED_POLICY)
}

func TestLicenseExpressionSingleCompoundInvalid(t *testing.T) {
	EXP := "()"
	EXPECTED_POLICY := schema.POLICY_UNDEFINED
	innerTestLicenseExpressionParsing(t, EXP, EXPECTED_POLICY)
}

func TestLicenseExpressionSingleCompoundInvalidAND(t *testing.T) {
	EXP := "AND"
	EXPECTED_POLICY := schema.POLICY_UNDEFINED
	innerTestLicenseExpressionParsing(t, EXP, EXPECTED_POLICY)
}

func TestLicenseExpressionSingleCompoundInvalidOR(t *testing.T) {
	EXP := "OR"
	EXPECTED_POLICY := schema.POLICY_UNDEFINED
	innerTestLicenseExpressionParsing(t, EXP, EXPECTED_POLICY)
}

func TestLicenseExpressionSingleCompoundInvalidAND2(t *testing.T) {
	EXP := "AND GPL-2.0-only"
	EXPECTED_POLICY := schema.POLICY_DENY
	innerTestLicenseExpressionParsing(t, EXP, EXPECTED_POLICY)
}

func TestLicenseExpressionSingleCompoundInvalidOR2(t *testing.T) {
	EXP := "OR GPL-2.0-only"
	EXPECTED_POLICY := schema.POLICY_DENY
	innerTestLicenseExpressionParsing(t, EXP, EXPECTED_POLICY)
}

// ---------------------------
// License Policy Config tests
// ---------------------------
const (
	// Test custom license policy (with license expression)
	TEST_CUSTOM_POLICY_1                           = "test/policy/license-policy-expression-outer-parens.policy.json"
	TEST_LICENSE_LIST_TEXT_CDX_1_4_CUSTOM_POLICY_1 = "test/policy/license-policy-expression-outer-parens.bom.json"
)

// TODO: uncomment once we have a means to dynamically pass in the license config. object
func TestLicenseListPolicyCdx14CustomPolicy(t *testing.T) {
	TEST_LICENSE_HUMAN_READABLE_EXPRESSION := "( MIT License OR Creative Commons Zero v1.0 Universal )"
	TEST_LICENSE_URLS := "https://opensource.org/licenses/MIT, https://creativecommons.org/publicdomain/zero/1.0/legalcode"

	lti := NewLicenseTestInfo(TEST_LICENSE_LIST_TEXT_CDX_1_4_CUSTOM_POLICY_1, FORMAT_TEXT, true)
	lti.ResultLineContainsValues = []string{schema.POLICY_ALLOW, TEST_LICENSE_HUMAN_READABLE_EXPRESSION, TEST_LICENSE_URLS}
	lti.ResultLineContainsValuesAtLineNum = 2
	lti.PolicyFile = TEST_CUSTOM_POLICY_1

	// Load a custom policy file ONLY for the specific unit test
	innerTestLicenseList(t, lti)
}

// ---------------------------------
// CDX License hashing hashing tests
// ---------------------------------

func TestHashCDXLicense(t *testing.T) {
	//
	// Apache-2.0
	//
	EXPECTED_LICENSE := "Apache License Version 2.0"
	EXPECTED_LICENSE_URLS := "https://www.apache.org/licenses/LICENSE-2.0"
	EXPECTED_USAGE_POLICY := schema.POLICY_ALLOW

	CDX_LICENSE_NAME := "Apache License Version 2.0"
	CDX_LICENSE_URL := "https://www.apache.org/licenses/LICENSE-2.0"
	innerTestLicenseInfoHashing(t, CDX_LICENSE_NAME, CDX_LICENSE_URL, EXPECTED_LICENSE, EXPECTED_LICENSE_URLS, EXPECTED_USAGE_POLICY)

	CDX_LICENSE_NAME = "Apache License, Version 2.0"
	CDX_LICENSE_URL = "http://www.apache.org/licenses/LICENSE-2.0.txt"
	innerTestLicenseInfoHashing(t, CDX_LICENSE_NAME, CDX_LICENSE_URL, EXPECTED_LICENSE, EXPECTED_LICENSE_URLS, EXPECTED_USAGE_POLICY)

	CDX_LICENSE_NAME = "The Apache License, Version 2.0"
	CDX_LICENSE_URL = "http://www.apache.org/licenses/LICENSE-2.0.txt"
	innerTestLicenseInfoHashing(t, CDX_LICENSE_NAME, CDX_LICENSE_URL, EXPECTED_LICENSE, EXPECTED_LICENSE_URLS, EXPECTED_USAGE_POLICY)

	CDX_LICENSE_NAME = "The Apache Software License, Version 2.0"
	CDX_LICENSE_URL = "http://www.apache.org/licenses/LICENSE-2.0.txt"
	innerTestLicenseInfoHashing(t, CDX_LICENSE_NAME, CDX_LICENSE_URL, EXPECTED_LICENSE, EXPECTED_LICENSE_URLS, EXPECTED_USAGE_POLICY)

	CDX_LICENSE_NAME = "Apache 2.0"
	CDX_LICENSE_URL = "http://www.apache.org/licenses/LICENSE-2.0.txt"
	innerTestLicenseInfoHashing(t, CDX_LICENSE_NAME, CDX_LICENSE_URL, EXPECTED_LICENSE, EXPECTED_LICENSE_URLS, EXPECTED_USAGE_POLICY)

	CDX_LICENSE_NAME = "Apache 2.0"
	CDX_LICENSE_URL = "http://www.apache.org/licenses/LICENSE-2.0"
	innerTestLicenseInfoHashing(t, CDX_LICENSE_NAME, CDX_LICENSE_URL, EXPECTED_LICENSE, EXPECTED_LICENSE_URLS, EXPECTED_USAGE_POLICY)

	CDX_LICENSE_NAME = "ASF 2.0"
	CDX_LICENSE_URL = "http://www.apache.org/licenses/LICENSE-2.0.txt"
	innerTestLicenseInfoHashing(t, CDX_LICENSE_NAME, CDX_LICENSE_URL, EXPECTED_LICENSE, EXPECTED_LICENSE_URLS, EXPECTED_USAGE_POLICY)

	CDX_LICENSE_NAME = "Apache 2"
	CDX_LICENSE_URL = "http://www.apache.org/licenses/LICENSE-2.0.txt"
	innerTestLicenseInfoHashing(t, CDX_LICENSE_NAME, CDX_LICENSE_URL, EXPECTED_LICENSE, EXPECTED_LICENSE_URLS, EXPECTED_USAGE_POLICY)

	CDX_LICENSE_NAME = "Apache License, Version 2.0"
	CDX_LICENSE_URL = ""
	innerTestLicenseInfoHashing(t, CDX_LICENSE_NAME, CDX_LICENSE_URL, EXPECTED_LICENSE, EXPECTED_LICENSE_URLS, EXPECTED_USAGE_POLICY)

	CDX_LICENSE_NAME = "Apache 2.0"
	CDX_LICENSE_URL = ""
	innerTestLicenseInfoHashing(t, CDX_LICENSE_NAME, CDX_LICENSE_URL, EXPECTED_LICENSE, EXPECTED_LICENSE_URLS, EXPECTED_USAGE_POLICY)

	CDX_LICENSE_NAME = "ASF 2.0"
	CDX_LICENSE_URL = ""
	innerTestLicenseInfoHashing(t, CDX_LICENSE_NAME, CDX_LICENSE_URL, EXPECTED_LICENSE, EXPECTED_LICENSE_URLS, EXPECTED_USAGE_POLICY)

	CDX_LICENSE_NAME = "The Apache Software License, Version 2.0"
	CDX_LICENSE_URL = ""
	innerTestLicenseInfoHashing(t, CDX_LICENSE_NAME, CDX_LICENSE_URL, EXPECTED_LICENSE, EXPECTED_LICENSE_URLS, EXPECTED_USAGE_POLICY)

	CDX_LICENSE_NAME = "https://www.apache.org/licenses/LICENSE-2.0.txt"
	CDX_LICENSE_URL = ""
	innerTestLicenseInfoHashing(t, CDX_LICENSE_NAME, CDX_LICENSE_URL, EXPECTED_LICENSE, EXPECTED_LICENSE_URLS, EXPECTED_USAGE_POLICY)

	CDX_LICENSE_NAME = "http://www.apache.org/licenses/LICENSE-2.0.txt"
	CDX_LICENSE_URL = ""
	innerTestLicenseInfoHashing(t, CDX_LICENSE_NAME, CDX_LICENSE_URL, EXPECTED_LICENSE, EXPECTED_LICENSE_URLS, EXPECTED_USAGE_POLICY)

	CDX_LICENSE_NAME = "http://www.apache.org/licenses/LICENSE-2.0.html"
	CDX_LICENSE_URL = ""
	innerTestLicenseInfoHashing(t, CDX_LICENSE_NAME, CDX_LICENSE_URL, EXPECTED_LICENSE, EXPECTED_LICENSE_URLS, EXPECTED_USAGE_POLICY)

	CDX_LICENSE_NAME = "http://www.opensource.org/licenses/apache2.0.php"
	CDX_LICENSE_URL = ""
	innerTestLicenseInfoHashing(t, CDX_LICENSE_NAME, CDX_LICENSE_URL, EXPECTED_LICENSE, EXPECTED_LICENSE_URLS, EXPECTED_USAGE_POLICY)

	CDX_LICENSE_NAME = "https://www.apache.org/licenses/LICENSE-2.0"
	CDX_LICENSE_URL = ""
	innerTestLicenseInfoHashing(t, CDX_LICENSE_NAME, CDX_LICENSE_URL, EXPECTED_LICENSE, EXPECTED_LICENSE_URLS, EXPECTED_USAGE_POLICY)

	CDX_LICENSE_NAME = "http://www.apache.org/licenses/LICENSE-2.0"
	CDX_LICENSE_URL = ""
	innerTestLicenseInfoHashing(t, CDX_LICENSE_NAME, CDX_LICENSE_URL, EXPECTED_LICENSE, EXPECTED_LICENSE_URLS, EXPECTED_USAGE_POLICY)

	//
	// Bouncy-Castle
	//
	EXPECTED_LICENSE = "Bouncy Castle Licence"
	EXPECTED_LICENSE_URLS = "https://www.bouncycastle.org/licence.html"
	EXPECTED_USAGE_POLICY = schema.POLICY_ALLOW

	CDX_LICENSE_NAME = "Bouncy Castle Licence"
	CDX_LICENSE_URL = ""
	innerTestLicenseInfoHashing(t, CDX_LICENSE_NAME, CDX_LICENSE_URL, EXPECTED_LICENSE, EXPECTED_LICENSE_URLS, EXPECTED_USAGE_POLICY)

	//
	// BSD-2-Clause
	//
	EXPECTED_LICENSE = "BSD 2-Clause \"Simplified\" License"
	EXPECTED_LICENSE_URLS = "https://opensource.org/licenses/BSD-2-Clause"
	EXPECTED_USAGE_POLICY = schema.POLICY_ALLOW

	CDX_LICENSE_NAME = "BSD"
	CDX_LICENSE_URL = "http://www.opensource.org/licenses/bsd-license.php"
	innerTestLicenseInfoHashing(t, CDX_LICENSE_NAME, CDX_LICENSE_URL, EXPECTED_LICENSE, EXPECTED_LICENSE_URLS, EXPECTED_USAGE_POLICY)

	CDX_LICENSE_NAME = "http://www.opensource.org/licenses/bsd-license.php"
	CDX_LICENSE_URL = ""
	innerTestLicenseInfoHashing(t, CDX_LICENSE_NAME, CDX_LICENSE_URL, EXPECTED_LICENSE, EXPECTED_LICENSE_URLS, EXPECTED_USAGE_POLICY)

	CDX_LICENSE_NAME = "https://raw.githubusercontent.com/jaxen-xpath/jaxen/master/LICENSE.txt"
	CDX_LICENSE_URL = ""
	innerTestLicenseInfoHashing(t, CDX_LICENSE_NAME, CDX_LICENSE_URL, EXPECTED_LICENSE, EXPECTED_LICENSE_URLS, EXPECTED_USAGE_POLICY)

	//
	// BSD-3-Clause
	//
	EXPECTED_LICENSE = "BSD 3-Clause \"New\" or \"Revised\" License"
	EXPECTED_LICENSE_URLS = "https://opensource.org/licenses/BSD-3-Clause"
	EXPECTED_USAGE_POLICY = schema.POLICY_ALLOW

	CDX_LICENSE_NAME = "BSD License"
	CDX_LICENSE_URL = "http://opensource.org/licenses/BSD-3-Clause"
	innerTestLicenseInfoHashing(t, CDX_LICENSE_NAME, CDX_LICENSE_URL, EXPECTED_LICENSE, EXPECTED_LICENSE_URLS, EXPECTED_USAGE_POLICY)

	CDX_LICENSE_NAME = "Revised BSD"
	CDX_LICENSE_URL = "http://www.jcraft.com/jsch/LICENSE.txt"
	innerTestLicenseInfoHashing(t, CDX_LICENSE_NAME, CDX_LICENSE_URL, EXPECTED_LICENSE, EXPECTED_LICENSE_URLS, EXPECTED_USAGE_POLICY)

	CDX_LICENSE_NAME = "BSD"
	CDX_LICENSE_URL = "http://opensource.org/licenses/BSD-3-Clause"
	innerTestLicenseInfoHashing(t, CDX_LICENSE_NAME, CDX_LICENSE_URL, EXPECTED_LICENSE, EXPECTED_LICENSE_URLS, EXPECTED_USAGE_POLICY)

	CDX_LICENSE_NAME = "New BSD License"
	CDX_LICENSE_URL = "https://opensource.org/licenses/BSD-3-Clause"
	innerTestLicenseInfoHashing(t, CDX_LICENSE_NAME, CDX_LICENSE_URL, EXPECTED_LICENSE, EXPECTED_LICENSE_URLS, EXPECTED_USAGE_POLICY)

	// License name -> BSD 3-Clause \"New\" or \"Revised\" License
	// License URL -> BSD 2-Clause "Simplified" License URL
	// => license name "wins"
	CDX_LICENSE_NAME = "New BSD License"
	CDX_LICENSE_URL = "http://www.opensource.org/licenses/bsd-license.php"
	innerTestLicenseInfoHashing(t, CDX_LICENSE_NAME, CDX_LICENSE_URL, EXPECTED_LICENSE, EXPECTED_LICENSE_URLS, EXPECTED_USAGE_POLICY)

	CDX_LICENSE_NAME = "The BSD License"
	CDX_LICENSE_URL = ""
	innerTestLicenseInfoHashing(t, CDX_LICENSE_NAME, CDX_LICENSE_URL, EXPECTED_LICENSE, EXPECTED_LICENSE_URLS, EXPECTED_USAGE_POLICY)

	CDX_LICENSE_NAME = "https://opensource.org/licenses/BSD-3-Clause"
	CDX_LICENSE_URL = ""
	innerTestLicenseInfoHashing(t, CDX_LICENSE_NAME, CDX_LICENSE_URL, EXPECTED_LICENSE, EXPECTED_LICENSE_URLS, EXPECTED_USAGE_POLICY)

	CDX_LICENSE_NAME = "http://www.debian.org/misc/bsd.license"
	CDX_LICENSE_URL = ""
	innerTestLicenseInfoHashing(t, CDX_LICENSE_NAME, CDX_LICENSE_URL, EXPECTED_LICENSE, EXPECTED_LICENSE_URLS, EXPECTED_USAGE_POLICY)

	CDX_LICENSE_NAME = "http://x-stream.github.io/license.html"
	CDX_LICENSE_URL = ""
	innerTestLicenseInfoHashing(t, CDX_LICENSE_NAME, CDX_LICENSE_URL, EXPECTED_LICENSE, EXPECTED_LICENSE_URLS, EXPECTED_USAGE_POLICY)

	// CC-PDDC
	EXPECTED_LICENSE = "Creative Commons Public Domain Dedication and Certification"
	EXPECTED_LICENSE_URLS = "https://creativecommons.org/publicdomain"
	EXPECTED_USAGE_POLICY = schema.POLICY_ALLOW

	CDX_LICENSE_NAME = "Public Domain"
	CDX_LICENSE_URL = ""
	innerTestLicenseInfoHashing(t, CDX_LICENSE_NAME, CDX_LICENSE_URL, EXPECTED_LICENSE, EXPECTED_LICENSE_URLS, EXPECTED_USAGE_POLICY)

	//
	// CDDL-1.1
	//
	EXPECTED_LICENSE = "Common Development and Distribution License 1.1"
	EXPECTED_LICENSE_URLS = "https://javaee.github.io/glassfish/LICENSE"
	EXPECTED_USAGE_POLICY = schema.POLICY_ALLOW

	CDX_LICENSE_NAME = "https://glassfish.java.net/public/CDDL+GPL_1_1.html, https://glassfish.java.net/public/CDDL+GPL_1_1.html"
	CDX_LICENSE_URL = ""
	innerTestLicenseInfoHashing(t, CDX_LICENSE_NAME, CDX_LICENSE_URL, EXPECTED_LICENSE, EXPECTED_LICENSE_URLS, EXPECTED_USAGE_POLICY)

	CDX_LICENSE_NAME = "https://oss.oracle.com/licenses/CDDL+GPL-1.1, https://oss.oracle.com/licenses/CDDL+GPL-1.1"
	CDX_LICENSE_URL = ""
	innerTestLicenseInfoHashing(t, CDX_LICENSE_NAME, CDX_LICENSE_URL, EXPECTED_LICENSE, EXPECTED_LICENSE_URLS, EXPECTED_USAGE_POLICY)

	CDX_LICENSE_NAME = "CDDL+GPL License"
	CDX_LICENSE_URL = ""
	innerTestLicenseInfoHashing(t, CDX_LICENSE_NAME, CDX_LICENSE_URL, EXPECTED_LICENSE, EXPECTED_LICENSE_URLS, EXPECTED_USAGE_POLICY)

	CDX_LICENSE_NAME = "https://glassfish.dev.java.net/public/CDDL+GPL_1_1.html"
	CDX_LICENSE_URL = ""
	innerTestLicenseInfoHashing(t, CDX_LICENSE_NAME, CDX_LICENSE_URL, EXPECTED_LICENSE, EXPECTED_LICENSE_URLS, EXPECTED_USAGE_POLICY)

	CDX_LICENSE_NAME = "https://github.com/javaee/activation/blob/master/LICENSE.txt"
	CDX_LICENSE_URL = ""
	innerTestLicenseInfoHashing(t, CDX_LICENSE_NAME, CDX_LICENSE_URL, EXPECTED_LICENSE, EXPECTED_LICENSE_URLS, EXPECTED_USAGE_POLICY)

	CDX_LICENSE_NAME = "https://github.com/javaee/javax.annotation/blob/master/LICENSE"
	CDX_LICENSE_URL = ""
	innerTestLicenseInfoHashing(t, CDX_LICENSE_NAME, CDX_LICENSE_URL, EXPECTED_LICENSE, EXPECTED_LICENSE_URLS, EXPECTED_USAGE_POLICY)

	//
	// EPL-1.0
	//
	EXPECTED_LICENSE = "Eclipse Public License 1.0"
	EXPECTED_LICENSE_URLS = "https://www.eclipse.org/legal/epl-v10.html"
	EXPECTED_USAGE_POLICY = schema.POLICY_ALLOW

	CDX_LICENSE_NAME = "Eclipse Public License 1.0"
	CDX_LICENSE_URL = "http://www.eclipse.org/legal/epl-v10.html"
	innerTestLicenseInfoHashing(t, CDX_LICENSE_NAME, CDX_LICENSE_URL, EXPECTED_LICENSE, EXPECTED_LICENSE_URLS, EXPECTED_USAGE_POLICY)

	CDX_LICENSE_NAME = "The Eclipse Public License Version 1.0"
	CDX_LICENSE_URL = "http://www.eclipse.org/legal/epl-v10.html"
	innerTestLicenseInfoHashing(t, CDX_LICENSE_NAME, CDX_LICENSE_URL, EXPECTED_LICENSE, EXPECTED_LICENSE_URLS, EXPECTED_USAGE_POLICY)

	CDX_LICENSE_NAME = "Eclipse Public License 1.0"
	CDX_LICENSE_URL = ""
	innerTestLicenseInfoHashing(t, CDX_LICENSE_NAME, CDX_LICENSE_URL, EXPECTED_LICENSE, EXPECTED_LICENSE_URLS, EXPECTED_USAGE_POLICY)

	//
	// EPL-2.0
	//
	EXPECTED_LICENSE = "Eclipse Public License 2.0"
	EXPECTED_LICENSE_URLS = "https://www.eclipse.org/legal/epl-2.0"
	EXPECTED_USAGE_POLICY = schema.POLICY_ALLOW

	CDX_LICENSE_NAME = "The Eclipse Public License Version 2.0"
	CDX_LICENSE_URL = "https://www.eclipse.org/legal/epl-v20.html"
	innerTestLicenseInfoHashing(t, CDX_LICENSE_NAME, CDX_LICENSE_URL, EXPECTED_LICENSE, EXPECTED_LICENSE_URLS, EXPECTED_USAGE_POLICY)

	CDX_LICENSE_NAME = "Eclipse Public License - v 2.0"
	CDX_LICENSE_URL = "https://www.eclipse.org/legal/epl-2.0/"
	innerTestLicenseInfoHashing(t, CDX_LICENSE_NAME, CDX_LICENSE_URL, EXPECTED_LICENSE, EXPECTED_LICENSE_URLS, EXPECTED_USAGE_POLICY)

	//
	// ICU
	//
	EXPECTED_LICENSE = "ICU License"
	EXPECTED_LICENSE_URLS = "https://raw.githubusercontent.com/unicode-org/icu/main/LICENSE"
	EXPECTED_USAGE_POLICY = schema.POLICY_ALLOW

	CDX_LICENSE_NAME = "Unicode/ICU"
	CDX_LICENSE_URL = "https://raw.githubusercontent.com/unicode-org/icu/main/LICENSE"
	innerTestLicenseInfoHashing(t, CDX_LICENSE_NAME, CDX_LICENSE_URL, EXPECTED_LICENSE, EXPECTED_LICENSE_URLS, EXPECTED_USAGE_POLICY)

	CDX_LICENSE_NAME = "Unicode/ICU License"
	CDX_LICENSE_URL = ""
	innerTestLicenseInfoHashing(t, CDX_LICENSE_NAME, CDX_LICENSE_URL, EXPECTED_LICENSE, EXPECTED_LICENSE_URLS, EXPECTED_USAGE_POLICY)

	//
	// MIT
	//
	EXPECTED_LICENSE = "MIT License"
	EXPECTED_LICENSE_URLS = "https://opensource.org/licenses/MIT"
	EXPECTED_USAGE_POLICY = schema.POLICY_ALLOW

	CDX_LICENSE_NAME = "MIT License"
	CDX_LICENSE_URL = "http://www.opensource.org/licenses/mit-license.php"
	innerTestLicenseInfoHashing(t, CDX_LICENSE_NAME, CDX_LICENSE_URL, EXPECTED_LICENSE, EXPECTED_LICENSE_URLS, EXPECTED_USAGE_POLICY)

	CDX_LICENSE_NAME = "The MIT license"
	CDX_LICENSE_URL = "http://www.opensource.org/licenses/mit-license.php"
	innerTestLicenseInfoHashing(t, CDX_LICENSE_NAME, CDX_LICENSE_URL, EXPECTED_LICENSE, EXPECTED_LICENSE_URLS, EXPECTED_USAGE_POLICY)

	CDX_LICENSE_NAME = "MIT license"
	CDX_LICENSE_URL = ""
	innerTestLicenseInfoHashing(t, CDX_LICENSE_NAME, CDX_LICENSE_URL, EXPECTED_LICENSE, EXPECTED_LICENSE_URLS, EXPECTED_USAGE_POLICY)

	CDX_LICENSE_NAME = "https://jsoup.org/license"
	CDX_LICENSE_URL = ""
	innerTestLicenseInfoHashing(t, CDX_LICENSE_NAME, CDX_LICENSE_URL, EXPECTED_LICENSE, EXPECTED_LICENSE_URLS, EXPECTED_USAGE_POLICY)

	//
	// Multiple licenses
	//
	EXPECTED_LICENSE = "GNU General Public License v2.0 only WITH Classpath exception 2.0 WITH OpenJDK Assembly exception 1.0"
	EXPECTED_LICENSE_URLS = "https://www.gnu.org/licenses/old-licenses/gpl-2.0-standalone.html, https://www.gnu.org/software/classpath/license.html, http://openjdk.java.net/legal/assembly-exception.html"
	EXPECTED_USAGE_POLICY = schema.POLICY_ALLOW

	CDX_LICENSE_NAME = "GPL-2.0-only WITH Classpath-exception-2.0 WITH OpenJDK-assembly-exception-1.0"
	CDX_LICENSE_URL = ""
	innerTestLicenseInfoHashing(t, CDX_LICENSE_NAME, CDX_LICENSE_URL, EXPECTED_LICENSE, EXPECTED_LICENSE_URLS, EXPECTED_USAGE_POLICY)

	EXPECTED_LICENSE = "Apache License Version 2.0 OR MIT License OR GNU General Public License v3.0 only"
	EXPECTED_LICENSE_URLS = "https://www.apache.org/licenses/LICENSE-2.0, https://opensource.org/licenses/MIT, https://www.gnu.org/licenses/gpl-3.0-standalone.html"
	EXPECTED_USAGE_POLICY = schema.POLICY_ALLOW

	CDX_LICENSE_NAME = "http://www.apache.org/licenses/LICENSE-2.0.txt, http://www.opensource.org/licenses/mit-license.php, https://www.gnu.org/licenses/gpl-3.0.en.html"
	CDX_LICENSE_URL = ""
	innerTestLicenseInfoHashing(t, CDX_LICENSE_NAME, CDX_LICENSE_URL, EXPECTED_LICENSE, EXPECTED_LICENSE_URLS, EXPECTED_USAGE_POLICY)

	EXPECTED_LICENSE = "Apache License Version 2.0 AND ( Apache License Version 2.0 AND BSD 3-Clause \"New\" or \"Revised\" License )"
	EXPECTED_LICENSE_URLS = "https://www.apache.org/licenses/LICENSE-2.0, https://www.apache.org/licenses/LICENSE-2.0, https://opensource.org/licenses/BSD-3-Clause"
	EXPECTED_USAGE_POLICY = schema.POLICY_ALLOW

	CDX_LICENSE_NAME = "Apache-2.0 AND (Apache-2.0 AND BSD-3-Clause)"
	CDX_LICENSE_URL = ""
	innerTestLicenseInfoHashing(t, CDX_LICENSE_NAME, CDX_LICENSE_URL, EXPECTED_LICENSE, EXPECTED_LICENSE_URLS, EXPECTED_USAGE_POLICY)

	EXPECTED_LICENSE = "Apache License Version 2.0 AND BSD 3-Clause \"New\" or \"Revised\" License AND BSD 2-Clause \"Simplified\" License AND MIT License AND ISC License AND Unicode Terms of Use AND ( GNU Lesser General Public License v2.1 or later OR Creative Commons Attribution 4.0 International )"
	EXPECTED_LICENSE_URLS = "https://www.apache.org/licenses/LICENSE-2.0, https://opensource.org/licenses/BSD-3-Clause, https://opensource.org/licenses/BSD-2-Clause, https://opensource.org/licenses/MIT, https://www.isc.org/licenses/, http://web.archive.org/web/20140704074106/http://www.unicode.org/copyright.html, https://www.gnu.org/licenses/old-licenses/lgpl-2.1-standalone.html, https://creativecommons.org/licenses/by/4.0/legalcode"
	EXPECTED_USAGE_POLICY = schema.POLICY_ALLOW

	CDX_LICENSE_NAME = "Apache-2.0 AND BSD-3-Clause AND BSD-2-Clause AND MIT AND ISC AND Unicode-TOU AND (LGPL-2.1-or-later OR CC-BY-4.0)"
	CDX_LICENSE_URL = ""
	innerTestLicenseInfoHashing(t, CDX_LICENSE_NAME, CDX_LICENSE_URL, EXPECTED_LICENSE, EXPECTED_LICENSE_URLS, EXPECTED_USAGE_POLICY)
}

func TestHashNoLicense(t *testing.T) {
	bom := schema.NewBOM("dummyBomFile")

	err := hashLicenseInfoByLicenseType(bom, LicensePolicyConfig, schema.LicenseInfo{}, make([]common.WhereFilter, 0))
	if err == nil {
		t.Errorf("no error raised upon attempt to hash no/empty license info")
		return
	}
}
