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
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"un/pkg/url"
)

func init() {
	log.SetFlags(0)
	flag.Usage = func() {
		w := flag.CommandLine.Output()
		_, _ = fmt.Fprintln(w, "normalize_url normalizes URLs. Input must be urls line by line (from file or STDIN, read Usage section)")
		_, _ = fmt.Fprintln(w, "")
		_, _ = fmt.Fprintln(w, "Usage:")
		_, _ = fmt.Fprintf(w, "  normalize_url [-f FILENAME] [-o FILENAME] [-s]\n")
		_, _ = fmt.Fprintln(w, "")
		_, _ = fmt.Fprintln(w, "Options:")
		flag.PrintDefaults()
		_, _ = fmt.Fprintln(w, "")
		_, _ = fmt.Fprintln(w, "Examples:")
		_, _ = fmt.Fprintf(w, "  normalize_url -f urls.txt -o normalized_urls.txt\n\n")
		_, _ = fmt.Fprintf(w, "  cat urls.txt | normalize_url > normalized_urls.txt\n\n")
		_, _ = fmt.Fprintf(w, "  # Strict mode enabled. Any parsing error stops processing\n")
		_, _ = fmt.Fprintf(w, "  normalize_url -f urls.txt -o normalized_urls.txt -s\n")
	}
}

func main() {
	var iFile string
	var oFile string
	var strictMode bool

	flag.StringVar(&iFile, "f", "", "Input filename (STDIN if omitted)")
	flag.StringVar(&oFile, "o", "", "Output filename (STDOUT if omitted)")
	flag.BoolVar(&strictMode, "s", false, "Strict mode. Stop processing after the first error.")
	flag.Parse()

	in, err := openFile(iFile, os.Stdin)
	if err != nil {
		log.Fatal(err)
	}
	defer in.Close()

	out, err := openFile(oFile, os.Stdout)
	if err != nil {
		log.Fatal(err)
	}
	defer out.Close()

	ctx, cancel := context.WithCancel(context.Background())

	succeeded := 0
	failed := 0
	for line := range lines(ctx, in) {
		if line.Empty() {
			continue
		}

		u, err := url.NormalizeURL(line.Url)
		if err != nil {
			failed++
			log.Println(fmt.Sprintf("parse error at \"%s:%d\": %s", iFile, line.Pos, line.Url))
			if strictMode {
				cancel()
				break
			}
			continue
		}

		_, err = out.WriteString(fmt.Sprintf("%s\n", u))
		if err != nil {
			cancel()
			log.Println(err)
			break
		}

		succeeded++
	}

	log.Printf("normalized: %d; failed: %d", succeeded, failed)
}

type Line struct {
	Url string
	Pos int
}

func (l Line) Empty() bool {
	return l.Url == ""
}

func openFile(fname string, def *os.File) (*os.File, error) {
	if fname != "" {
		return os.Open(fname)
	}
	return def, nil
}

func lines(ctx context.Context, f *os.File) chan Line {
	ch := make(chan Line, 10)

	go func() {
		defer close(ch)

		pos := 0

		scanner := bufio.NewScanner(f)
		scanner.Split(bufio.ScanLines)

		for {
			select {
			case <-ctx.Done():
				return
			default:
				if !scanner.Scan() {
					return
				}
				pos++
				u := scanner.Text()
				ch <- Line{
					Url: u,
					Pos: pos,
				}
			}
		}
	}()

	return ch
}
