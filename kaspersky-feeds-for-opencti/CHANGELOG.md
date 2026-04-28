# What's new in Kaspersky TI connector for OpenCTI

## [1.1.2]

### OpenCTI work tracking
- Each synchronization run is now registered as a dedicated OpenCTI work/task, with work status, errors and completion details propagated to the platform UI.

### Label and description controls
- Added `connector.label_format` / `CONNECTOR_LABEL_FORMAT` with `legacy`, `new` and `both` modes for connector-authored labels on indicators and observables.
- Added `connector.description_mode` / `CONNECTOR_DESCRIPTION_MODE` with `overwrite`, `skip` and `create_only` modes for outgoing descriptions.

## [1.1.1] - 2026-03-01
 
### Performance
- Send STIX 2.1 objects to OpenCTI in bundles of up to 1000 objects per request (instead of sending one object per request), improving ingestion speed for large datasets.
 
### OpenCTI metadata
- Indicators now include `x_opencti_main_observable_type` derived from the STIX pattern (IPv4-Addr, IPv6-Addr, File, Domain-Name, Url, Email-Addr) to improve OpenCTI classification/display.
 
### Threat score handling
- Added `connector.threat_score_from_description`: when enabled, `x_opencti_score` is taken from `threat_score=` inside `description` (or `x_opencti_description`), and threat-score labels are not generated (`threat_score:kaspersky:high|medium|low`).
 
### Indicator/observable creation switch
- Added (and wired) `kaspersky.create_indicators` and `kaspersky.create_observables` (effective when `kaspersky.expand_objects: true`):
  - `create_indicators: false` disables emitting Indicator objects.
  - `create_observables: false` disables generating Observables from indicator patterns.
  - In observables-only mode (`create_indicators: false`, `create_observables: true`), relationships that were previously created from Indicators are created from the generated Observable (File, DomainName, URL, IPv4Address) to preserve links to related entities.

### Reliability
- Fixed state persistence for one-shot runs (`connector.run_and_terminate: true`) by forcing state synchronization with OpenCTI before process exit.
- Improved incremental watermark handling: the state now advances at least to run start time, preventing repeated imports when feed metadata timestamps do not track TAXII `added_after` semantics.
- Reduced noisy retries for normal no-data polling: TAXII `404` responses for empty `added_after` windows are no longer retried.
- Fixed threat-actor ID generation path for `pycti < 6.4` in `actors_transform` (legacy compatibility path).

## [1.1.0] - 2025-12-06

### Upgrade notes

This release changes how indicators, observables, relationships and TAXII incremental collection windows are handled.
To make sure your OpenCTI graph is consistent and no data is lost, you **must** reinitialize the connector after upgrading:

- stop the existing connector instance
- reset the connector state in OpenCTI (Admin → Data → Connectors → your Kaspersky connector → Reset state)
- start the connector again so it performs a fresh synchronization with the updated logic

---

### Indicator names

- Indicator names are now derived directly from the STIX pattern value.
- For `URL LIKE` patterns, SQL-style wildcards `%` and `_` are converted to `*` and `?` to produce more readable, mask-like indicator names.

### Observable generation

- The connector now explicitly generates observables from indicator patterns.
- Supported observable types: `url`, `domain-name`, `ipv4-addr` and `file`.
- Fixed observable generation for `file` objects that contain multiple hashes.
- Added support for patterns with `LIKE`, including correct handling of wildcard masks.
- All indicators are linked to the corresponding observables via the `based-on` relationship.

### Confidence handling

- A `connector.confidence_level` configuration parameter controls the `confidence` value for entities and relationships created by the connector.
- The configured confidence value is applied to all relationships created by the connector (for example, between indicators, countries and threat actors).
- Confidence values that come directly from the feed (for indicators or IPs) are not overridden.

### Richer relationships in the graph

- Relationships created by the connector (including `indicates` and `based-on`) now inherit part of the metadata from the source objects:
  - `description`
  - `labels`
- This makes the OpenCTI graph easier to analyze and filter, since relationship metadata can now be used in searches and views in the same way as object metadata.

### Threat score and tagging

- A single `connector.threat_score` parameter now controls the `x_opencti_score` assigned to all created indicators and their related observables (URLs, IPs, hashes, etc.).
  If you configure the score as `80`, all newly created indicators will receive `x_opencti_score = 80`, regardless of type.
- The `connector.threat_score_high` and `connector.threat_score_medium` thresholds drive automatic threat-level tags:
  - `threat_score:kaspersky:high`
  - `threat_score:kaspersky:medium`
  - `threat_score:kaspersky:low`
- If an object description contains a fragment like `threat_score=NN`, the connector parses this value and assigns the corresponding threat-level tag based on the configured thresholds.

### Activity label normalization

- Activity labels from the feeds are normalized for consistency:
  - `malicious-activity` is automatically converted to `malicious-activity:kaspersky`.
- This simplifies filtering by activity type and source in OpenCTI.

### TAXII ingestion and reliability

- A new `kaspersky.connection_timeout` configuration parameter defines the HTTP timeout (in seconds) for all TAXII requests.
- Object retrieval from TAXII collections now uses automatic retries:
  - up to 3 attempts on transient network errors
  - with logging and increasing delay between attempts
- The incremental collection window has been reworked to avoid data loss when TAXII delivers objects "in the past":
  - previously, the connector fetched “last hour” of data every hour, which could miss indicators with backdated timestamps
  - now, the connector requests new data starting from the `created` timestamp of the most recently ingested indicator, ensuring late-arriving indicators are still collected

### OpenCTI / pycti compatibility

- Threat actor ID generation is adapted for pycti 6.4+ while preserving the previous behavior for older versions.
- This prevents duplicate threat actors and ID conflicts across OpenCTI versions and keeps the connector compatible with both new and legacy deployments.

### New configuration parameters

The following parameters are available in `config.yml` and via environment variables:

- `connector.confidence_level`
  Controls the `confidence` value for entities and relationships created by the connector.

- `connector.threat_score`
  Controls the `x_opencti_score` assigned to all created indicators.

- `connector.threat_score_high`, `connector.threat_score_medium`
  Define thresholds used to assign threat-level tags (`threat_score:kaspersky:high/medium/low`).

- `kaspersky.connection_timeout`
  HTTP timeout for TAXII requests in seconds; used by all TAXII client operations, with automatic retries on failures.
