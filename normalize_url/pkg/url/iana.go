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
	"embed"
	"log"
)

const DefaultScheme = "http"

//go:embed iana.txt
var fs embed.FS

type ianaSchemes map[string]struct{}

func (s ianaSchemes) IsValid(scheme string) bool {
	_, valid := s[scheme]
	return valid
}

var IANASchemes ianaSchemes

func init() {
	f, err := fs.Open("iana.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	IANASchemes = make(map[string]struct{})

	scanner := bufio.NewScanner(f)
	scanner.Split(bufio.ScanLines)

	for scanner.Scan() {
		scheme := scanner.Text()
		IANASchemes[scheme] = struct{}{}
	}
}
