// © 2024 AO Kaspersky Lab. All Rights Reserved.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package ip

import (
	"fmt"
	"testing"
)

func ExampleNormalizeIPv4() {
	ip, _ := NormalizeIPv4("0xa40300b")
	fmt.Println(ip)
	ip, _ = NormalizeIPv4("0xa.0x40.0x30.0xb")
	fmt.Println(ip)
	ip, _ = NormalizeIPv4("30.31.8225")
	fmt.Println(ip)
	ip, _ = NormalizeIPv4("30.2039841")
	fmt.Println(ip)
	ip, _ = NormalizeIPv4("171978763")
	fmt.Println(ip)
	// Output:
	// 10.64.48.11
	// 10.64.48.11
	// 30.31.32.33
	// 30.31.32.33
	// 10.64.48.11
}

func ExampleNormalizeIPv6() {
	ip, _ := NormalizeIPv6("2001:0000:11AA:0000:0000:0000:1234:0000")
	fmt.Println(ip)
	// Output:
	// 2001:0:11aa::1234:0
}

func TestIPv4Normalization(t *testing.T) {
	type testCase struct {
		input    string
		expected string
	}
	var cases = [...]testCase{
		{
			input:    "10.16.56.12",
			expected: "10.16.56.12",
		},
		{
			input:    "171978763",
			expected: "10.64.48.11",
		},
		{
			input:    "0xa40300b",
			expected: "10.64.48.11",
		},
		{
			input:    "0112.0175.0117.0150",
			expected: "74.125.79.104",
		},
		{
			input:    "0xa.0x40.0x30.0xb",
			expected: "10.64.48.11",
		},
		{
			input:    "30.31.8225",
			expected: "30.31.32.33",
		},
		{
			input:    "30.2039841",
			expected: "30.31.32.33",
		},
	}
	for _, tt := range cases {
		result, err := NormalizeIPv4(tt.input)
		if err != nil {
			t.Error(err)
		}
		if tt.expected != result {
			t.Errorf("input: '%s', expected: '%v', actual: '%v'", tt.input, tt.expected, result)
		}
	}
}

func TestIPv6Normalization(t *testing.T) {
	type testCase struct {
		input    string
		expected string
	}
	var cases = [...]testCase{
		{
			input:    "2001:db8:3333:4444:5555:6666:7777:8888",
			expected: "2001:db8:3333:4444:5555:6666:7777:8888",
		},
		{
			input:    "2001:0000:11AA:0000:0000:0000:1234:0000",
			expected: "2001:0:11aa::1234:0",
		},
		{
			input:    "0000:0000:0000:0000:0000:0000:0000:0001",
			expected: "::1",
		},
		{
			input:    "0000:0000:0000:0000:0000:0000:0000:0000",
			expected: "::",
		},
		{
			input:    "2002:7F0:01Fa::0001",
			expected: "2002:7f0:1fa::1",
		},
	}
	for _, tt := range cases {
		result, err := NormalizeIPv6(tt.input)
		if err != nil {
			t.Error(err)
		}
		if tt.expected != result {
			t.Errorf("input: '%s', expected: '%v', actual: '%v'", tt.input, tt.expected, result)
		}

		bracedInput := fmt.Sprintf("[%s]", tt.input)
		bracedExpected := fmt.Sprintf("[%s]", tt.expected)
		bracedResult, err := NormalizeIPv6(bracedInput)
		if err != nil {
			t.Error(err)
		}
		if bracedExpected != bracedResult {
			t.Errorf("input: '%s', expected: '%v', actual: '%v'", bracedInput, bracedExpected, bracedResult)
		}
	}
}
