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
package url

import (
	"bufio"
	"os"
	"strings"
	"testing"
)

const filename = "testdata/urls.csv"

func TestNormalizeURL(t *testing.T) {
	for tt := range tests() {
		res, err := NormalizeURL(tt.orig)

		if err != nil {
			t.Fatalf("%v at line: %d\nurl: %s", err, tt.pos, tt.orig)
		}

		if res != tt.normalized {
			t.Fatalf("\nexpected:\t%s\n\tactual: %s\n  at line: %d", tt.normalized, res, tt.pos)
		}
	}
}

type testCases struct {
	orig       string
	normalized string
	pos        int
}

func tests() chan testCases {
	ch := make(chan testCases, 1)

	sep := "\t"

	go func() {
		defer close(ch)

		f, err := os.Open(filename)
		if err != nil {
			return
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		scanner.Split(bufio.ScanLines)

		pos := 0
		for scanner.Scan() {
			pos++
			line := scanner.Text()
			cols := strings.Split(line, sep)
			if len(cols) == 2 {
				ch <- testCases{
					orig:       cols[0],
					normalized: cols[1],
					pos:        pos,
				}
			}
		}
	}()

	return ch
}
