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

package utils

import (
	"bufio"
	"bytes"
	"encoding/json"
)

func IsJsonMapType(any interface{}) (isMapType bool) {
	_, isMapType = any.(map[string]interface{})
	return
}

func IsJsonSliceType(any interface{}) (isSliceType bool) {
	_, isSliceType = any.([]interface{})
	return
}

func IsValidJsonMap(test string) bool {
	var js map[string]interface{}
	err := json.Unmarshal([]byte(test), &js)
	return err == nil
}

func IsValidJsonRaw(test []byte) bool {
	var js interface{}
	err := json.Unmarshal(test, &js)
	return err == nil
}

// NOTE: simple wrapper method on json package to standardize parms
// WARNING: By default, json.Marshal() methods will use a unicode encoding
// which will encode utf8 characters such as: '@', '<', '>', etc.
func MarshalAnyToFormattedJsonString(any interface{}) (string, error) {
	// Indent each level with 2 space chars.
	byteMapOut, err := json.MarshalIndent(any, "", "  ")
	return string(byteMapOut), err
}

func MarshalStructToJsonMap(any interface{}) (mapOut map[string]interface{}, err error) {
	// TODO: validate input parameter is a struct
	var bytesOut []byte
	bytesOut, err = json.Marshal(any)

	if err != nil {
		return
	}
	err = json.Unmarshal(bytesOut, &mapOut)
	return
}

// NOTE: Using this custom encoder avoids the json.Marshal() default
// behavior of encoding utf8 characters such as: '@', '<', '>', etc.
// as unicode.
func EncodeAnyToIndentedJSON(any interface{}) (outputBuffer bytes.Buffer, err error) {
	bufferedWriter := bufio.NewWriter(&outputBuffer)
	encoder := json.NewEncoder(bufferedWriter)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "    ")
	err = encoder.Encode(any)
	// MUST ensure all data is written to buffer before further testing
	bufferedWriter.Flush()
	return
}

// TODO: function NOT complete, only placeholder type switch
// TODO: allow generic function to be applied to types
// func PrintTypes(values ...interface{}) {
// 	//fmt.Printf("values=%v\n", values)
// 	for index, value := range values {
// 		fmt.Printf("value[%d] (%T): %+v\n", index, value, value)
// 		switch t := value.(type) {
// 		case nil:
// 			fmt.Println("Type is nil.")
// 		case int:
// 		case uint:
// 		case int32:
// 		case int64:
// 		case uint64:
// 			fmt.Println("Type is an integer:", t)
// 		case float32:
// 		case float64:
// 			fmt.Println("Type is a float:", t)
// 		case string:
// 			fmt.Println("Type is a string:", t)
// 		case bool:
// 			fmt.Println("Type is a bool:", t)
// 		default:
// 			fmt.Printf("Type is unknown!: %v\n", t)
// 		}
// 	}
// }
