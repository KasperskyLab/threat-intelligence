# URL Normalizer

## Introduction
[Kaspersky Threat Data Feeds](https://support.kaspersky.com/datafeeds/about/13849) use specific URL normalization rules to standardize URLs before matching them against URL-based databases (such as Malicious URLs, Phishing URLs, Botnet C&C). These normalization rules improve matching accuracy by ensuring a consistent URL format. Using this utility converts URLs from network traffic into the standardized format required by Kaspersky Threat Data Feeds, enhancing the effectiveness of URL-based threat detection. If a URL does not meet the specified criteria, it's marked invalid with an error message displayed.

## Table of Contents

  * [Preparatory steps](#preparatory-steps)
    * [Install Go](#install-go)
  * [Build](#build)
  * [Usage](#usage)
    * [Examples](#examples)
  * [Description of URL normalization rules](#description-of-url-normalization-rules)
    * [Features of normalizing URLs using the utility](#features-of-normalizing-urls-using-the-utility)

## Preparatory steps

### Install Go

Instructions for installing Go on Linux/MacOS/Windows can be found at: https://go.dev/doc/install.

> Recommended version 1.22+

## Build

```bash
go build -o bin/normaize_url -trimpath ./cmd/...
```

For more information about build, see: https://pkg.go.dev/cmd/go#hdr-Compile_packages_and_dependencies

> For *nix systems, you can locate the file to `/usr/local/bin`.

## Usage

To display the help:
```bash
./normalize_url -h
```
The utility accepts URLs in two ways: by specifying a file with the `-f FILENAME` command line option, or by reading from `STDIN` when no input file is provided.
Similarly, output can be saved to a file with the `-o FILENAME` option or directed to `STDOUT` if no output file is specified.
The utility writes normalized URLs to `STDOUT` (or to a file if the -o option is used) and logs messages to `STDERR`.

### Examples

**urls.txt:**
```text
https://example.com
https://example.com:443/path?q=hello%20world
example.com
```

```bash
# Normalize URLs from the urls.txt file and write the normalized URLs and logs to separate files:
cat urls.txt | ./normalize_url > normalized_urls.txt 2> logs.txt

# Normalize URLs from the urls.txt file. Write the normalized URLs to a file, and write the logs to STDERR:
cat urls.txt | ./normalize_url -o normalized_urls.txt

# Read from a file and write to a file. Write logs to STDERR:
./normalize_url -f urls.txt -o normalized_urls.txt

# Read from a file and write to a file. Write logs to STDERR. Strict mode: stop normalization if an error occurs:
./normalize_url -f urls.txt -o normalized_urls.txt -s
```
## Description of URL normalization rules
Refer to the help section for a description of the general URL normalization rules applied by the utility: [URL normalization rules](https://tip.kaspersky.com/Help/TIDF/en-US/UrlNormalizationRules.htm)

### Features of normalizing URLs using the utility

- **not supported** automatic conversion of internationalized domain names based on the Punycode algorithm described in RFC 3492 (https://www.ietf.org/rfc/rfc3492.txt)

- **singly convert** percent-encoded symbols to UTF-8, according to RFC 3986 (https://www.ietf.org/rfc/rfc3986.txt) and RFC 2279 (https://www.ietf.org/rfc/rfc2279.txt) 
