# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

## 0.3.0 - 2024-06-09

### Added

- Search docker URLs when searching for URL SCOs
- Ignore observables with the empty SHA-256 hash
  (e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855)
- Create file SCOs from Office 365 logs in enrichment
- Create directory SCOs from Office 365 logs in enrichment
- Use vulnerability score for vulnerability_incident_cvss3_score_threshold
  check if CVSS3 score is unavailable
- Search directories in Office 365
- Add a small sleep() of 100 ms, potentially solving
  [#11](https://github.com/misje/opencti-wazuh-connector/issues/11)
- New setting *rule_exclude_list* that allows for ignoring certain alert rules
  altogether
- New setting *incident_rule_exclude_list* that prevents incident creation for
  certain alert rules
- Mention in *event creation* in docs that incidents from sighted
  vulnerabilities are not created by default unless configured
- Document alert rules in glossary, with screenshots of the rule viewer in
  Wazuh
- Add a timeout to OpenSearch queries (default 20 s), preventing a complete
  freeze if OpenSearch fails to reply
- Add new setting *vulnerability_incident_active_only* that allows for only
  creating incidents for sighted vulnerabilities if they are no longer active

### Changed

- OpenCTI 6.1.10 is used
- No longer enrich URLs without host and scheme by default (e.g. "/",
  "/foo/bar"), but leave the possibility as a new configuration option,
  *enrich_urls_without_host".
- If the vulnerability being enriched does not contain any CVSS3 information,
  extract this from alerts before running the logic in
  *vulnerability_incident_cvss3_score_threshold*. This allows for creating
  incidents based on CVSS score threshold even if this information is not
  present in the source entity.

### Fixed

- Avoid crashing when enriching untriaged vulnerabilities (when *published* is
  not set)
- Set confidence explicitly for sightings as a workaround for OpenCTI bug
  #6835. This ensures that sightings now get the correct confidence (that of
  the user/group running the connector).
- Fix bug in vulnerability_incident_cvss3_score_threshold logic
- Fix a number of typos and bugs in documentation
- Do not use months in timedeltas in tests, causing issues with 30/31 days in a
  month
- Remove "Observable" from incident description, since not all enriched
  entities are observables
- Do not match file names partially (regex mistake)

### Removed

- Remove all traces of the Wazuh API. It was only partially implemented, and
  will be added back when development of this as a separate enhancement is
  completed.
- Remove some debug output

## 0.2.1 - 2024-05-24

### Changed

- OpenCTI 6.1.4 is used

### Fixed

- References to docker image in documentation has been corrected (#38)

## 0.2.0 - 2024-05-15

### Added

- Enrich User-Account (user_id) from SIDs in registry keys
- Search registry keys with a number of options, include partial matches,
  ignoring SIDs in keys, and accepting several hive name formats

### Changed

- Use OpenCTI API version 6.1.1 and test against this version

### Fixed

- Use correct section level in config reference docs.
- Fix spelling and other minor details in docs
- Use correct setting names (with WAZUH\_ prefix) in docker-compose examples
- When enriching reg. keys, include full path (a bug caused only the hive name
  to be produced)
- Fix lucene regex escaping: only escape single backslashes
- Fix path escaping: Don't search-replace a minimum of two backslashes. One is
  enough

## 0.1.0 - 2024-05-11

Initial release
