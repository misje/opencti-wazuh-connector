# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

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
