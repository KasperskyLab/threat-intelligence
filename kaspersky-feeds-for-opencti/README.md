# Kaspersky Feeds for OpenCTI Connector

Kaspersky Feeds for OpenCTI connector imports threat data feeds in STIX 2.1 format from the Kaspersky Threat Intelligence Portal over the TAXII 2.1 API (https://taxii.tip.kaspersky.com/taxii2/) into OpenCTI.  
The connector periodically polls TAXII collections exposed by Kaspersky and pushes the received objects to OpenCTI using the pycti client.
When enabled in the configuration, the connector can also analyse the `description` field of incoming STIX objects to derive additional STIX 2 objects and relationships (for example, observables and context entities).

## Requirements

- OpenCTI Platform 5.9.0 and later
- Access token to the Kaspersky Threat Intelligence Portal TAXII server
- Python 3.12.0 and later (if you launch the connector manually, without OCI runtime)

**Note:** The connector communicates with OpenCTI platform not only via HTTP(s) protocol, but also through the RabbitMQ on the port configured in the OpenCTI platform. So the last ones should be configured properly, as well as firewall rules in your network environment.

## Installation

Kaspersky Feeds for OpenCTI connector is distributed only in form of source code, so you need to clone the KasperskyLab Threat Intelligence repository: 
```shell
git clone https://github.com/kasperskylab/threat-intelligence.git
cd threat-intelligence/kaspersky-feeds-for-opencti
```

## Version

Current stable version: **1.1.0**

See [CHANGELOG.md](./CHANGELOG.md) for the list of versions and changes.

## Upgrading to 1.1.0

Version 1.1.0 changes how indicators, observables, relationships and the TAXII incremental collection window are handled.  
To avoid inconsistent data and missed indicators, you must reinitialize the connector after upgrading:

1. Stop the running connector container or process.
2. In the OpenCTI UI, go to **Admin → Data → Connectors**, select the Kaspersky Feeds connector and use **Reset state**.
3. Start the connector again so that it performs a fresh synchronization with the new logic.

## Demo

![Kaspersky Feeds for OpenCTI demo](./docs/demo.gif)

## Usage

First, you need to check the current version of installed OpenCTI Platform and, if needed, update `src/requirements.txt` file, so that version of the `pycti` package is the same.
For example, if your OpenCTI Platform has version `5.9.6`, then `src/requirements.txt` file should be updated in the following way:
```
...
pycti==5.9.6
...
```

We recommend running this connector from a container, when appropriate.
To build docker container and use it with OCI runtime like Docker or Kubernetes, simply run the build command:
```shell
docker build -t kaspersky-feeds-for-opencti .
```

After successful build, you need to prepare configuration for the connector. Configuration parameters can be passed via configuration file or/and via environment variables. By default, the container looks for configuration file at the path `/app/config.yml`. The easiest way to prepare your configuration file is to copy sample configuration file `config.yml.sample` from sources:
```shell
cp src/config.yml.sample config.yml
```
Then modify parameters `opencti.url`, `opencti.token`, and `kaspersky.api_token` with actual values. Check section [Configuration](#configuration) to see the list of the available parameters and their description

**Note:** In case of test launches, it is recommended to replace `connector.run_and_terminate` parameter with value `true` to launch the connector in one-shot mode, as well as to replace `kaspersky.initial_history` parameter with some low value, like `3600` (equals to 1 hour), or reduce number of collections to use (for example, specify only `TAXII_Malicious_Hash_Data_Feed`) to receive less data from TAXII server.

After successful build and prepared configuration, you can integrate produced container into your virtualization infrastructure or you can just launch the container by Docker locally to check the container:
```shell
docker run --rm -it --volume $(pwd)/config.yml:/app/config.yml kaspersky-feeds-for-opencti:latest
```

## Configuration

The connector looks for `config.yml` in the current directory to read configuration. 
**Note:** In case of Docker container usage, the "current directory" is `/app`.

Optionally, many of the configuration settings can be handled solely by environment variables as described in the table below. This can be helpful to spin up a quick container to only specify what you need, beyond the defaults.

<div style="overflow-x: auto;">

| YAML Parameter                   | Environment Variable             | Mandatory | Description                                                                                                                                                   |
| -------------------------------- | -------------------------------- | --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `opencti.url`                    | `OPENCTI_URL`                    | Yes       | The URL of the OpenCTI platform.                                                                                                                              |
| `opencti.token`                  | `OPENCTI_TOKEN`                  | Yes       | Access token to the OpenCTI platform.                                                                                                                         |
| `opencti.ssl_verify`             | `OPENCTI_SSL_VERIFY`             | No        | Whether to use TLS certificate validation for connection with the OpenCTI platform.<br>Default: `true`.                                                       |
| `connector.id`                   | `CONNECTOR_ID`                   | Yes       | Unique identifier for the connector in form of UUIDv4 value.                                                                                                  |
| `connector.name`                 | `CONNECTOR_NAME`                 | No        | Name of the connector to identify it in OpenCTI platform.<br>Default: `Kaspersky Feeds`.                                                                      |
| `connector.scope`                | `CONNECTOR_SCOPE`                | No        | Scope of the connector.<br>Default: `kaspersky`.                                                                                                              |
| `connector.confidence_level`     | `CONNECTOR_CONFIDENCE_LEVEL`     | No        | Default confidence level for entities and relationships created by the connector (0–100). Feed-provided confidence values (for example on indicators or IP addresses) are not overridden.                  |
| `connector.threat_score`         | `CONNECTOR_THREAT_SCORE`         | No        | Default `x_opencti_score` applied to all indicators and their related observables created by the connector (0–100). The same score is used for URLs, IP addresses, file hashes and other indicator types. |
| `connector.threat_score_high`    | `CONNECTOR_THREAT_SCORE_HIGH`    | No        | Threshold value: objects with score greater than or equal to this value receive the label `threat_score:kaspersky:high`.<br>Default: `75`.                                                                 |
| `connector.threat_score_medium`  | `CONNECTOR_THREAT_SCORE_MEDIUM`  | No        | Threshold value: objects with score greater than or equal to this value and lower than `connector.threat_score_high` receive the label `threat_score:kaspersky:medium`. Objects below this threshold receive `threat_score:kaspersky:low`.<br>Default: `50`. |
| `kaspersky.connection_timeout`   | `KASPERSKY_CONNECTION_TIMEOUT`   | No        | HTTP timeout in seconds for all TAXII requests to the Kaspersky server. This value is used together with the connector’s automatic retry logic for polling TAXII collections.<br>Default: `60`.           |
| `connector.log_level`            | `CONNECTOR_LOG_LEVEL`            | No        | The log level for the connector, can be debug, info, warn or error (less verbose).<br>Default: `info`.                                                        |
| `connector.update_existing_data` | `CONNECTOR_UPDATE_EXISTING_DATA` | No        | Whether to update data for the stix2 objects that already exist in the OpenCTI platform.<br>Default: `false`.                                                 |
| `kaspersky.api_root`             | `KASPERSKY_API_ROOT`             | No        | API Root of the Kaspersky Threat Intelligence Portal TAXII server.<br>Default: `https://taxii.tip.kaspersky.com/v2`.                                          |
| `kaspersky.connection_timeout`   | `KASPERSKY_CONNECTION_TIMEOUT`   | No        | Timeout in seconds applied for all requests to the Kaspersky Threat Intelligence Portal TAXII server.<br>Default: `60`.                                       |
| `kaspersky.api_token`            | `KASPERSKY_API_TOKEN`            | Yes       | Access token to the Kaspersky Threat Intelligence Portal TAXII server.                                                                                        |
| `kaspersky.ssl_verify`           | `KASPERSKY_SSL_VERIFY`           | No        | Whether to use TLS certificate validation for connection with the Kaspersky Threat Intelligence Portal TAXII server.<br>Default: `true`.                      |
| `kaspersky.initial_history`      | `KASPERSKY_INITIAL_HISTORY`      | No        | The offset (in seconds) from the current time to the past, defining the start point for data import.<br>Default: `604800`.                                    |
| `kaspersky.update_interval`      | `KASPERSKY_UPDATE_INTERVAL`      | No        | Interval (in seconds) between updates execution.<br>Default: `3600`.                                                                                          |
| `kaspersky.expand_objects`       | `KASPERSKY_EXPAND_OBJECTS`       | No        | Whether to generate additional stix2 objects based on analysis of indicator's description content.<br>Default: `true`.                                        |
| `kaspersky.collections`          | `KASPERSKY_COLLECTIONS`          | No        | List of collections to import from TAXII server. Both UID and alias (with wildcards) can be used to specify collection.<br>Default: `TAXII_*_Data_Feed`.      |

</div>

**Note:** It is not recommended to use too large a value for configuration parameter `kaspersky.initial_history`, because it may result in a large amount of data being received from TAXII server.

**Note:** We strongly recommend to keep the `true` value for parameters `opencti.ssl_verify` and `kaspersky.ssl_verify`. If the `false` value for these parameters is specified, the connector will accept any TLS certificate presented by the server and will ignore hostname mismatches and/or expired certificates, which will make your application vulnerable to man-in-the-middle (MitM) attacks.

## License

Copyright © 2024 AO Kaspersky Lab

Licensed under the Apache 2.0 License. See the LICENSE.txt file for details.
