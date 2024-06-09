#!/bin/python3
import os
import sys
import pytest
import random
import logging
from pycti import OpenCTIConnectorHelper
from pydantic import AnyHttpUrl

sys.path.insert(0, os.path.abspath("../../src"))
from wazuh.search import AlertSearcher
from wazuh.search_config import FileSearchOption, SearchConfig
from wazuh.opensearch import OpenSearchClient
from wazuh.opensearch_config import OpenSearchConfig
from wazuh.opensearch_dsl import Bool, MultiMatch, Regexp, Term
from test_common import osConf

random.seed(0)

fields = [
    "data.ChildPath",  # panda paps
    "data.ParentPath",  # panda paps
    "data.Path",  # panda paps
    "data.TargetPath",  # panda paps
    "data.audit.exe",
    "data.audit.execve.a1",
    "data.audit.execve.a2",
    "data.audit.execve.a3",
    "data.audit.execve.a4",
    "data.audit.execve.a5",
    "data.audit.execve.a6",
    "data.audit.execve.a7",
    "data.audit.file.name",
    "data.file",
    "data.office365.SourceFileName",
    "data.osquery.columns.path",
    "data.sca.check.file",
    "data.smbd.filename",
    "data.smbd.new_filename",
    "data.virustotal.source.file",
    "data.win.eventdata.file",
    "data.win.eventdata.filePath",
    "data.win.eventdata.image",
    "data.win.eventdata.parentImage",
    "data.win.eventdata.targetFilename",
    "syscheck.path",
]


def dummy_func(monkeypatch):
    pass


def searcher(monkeypatch, **kwargs):
    monkeypatch.setattr(OpenCTIConnectorHelper, "__init__", dummy_func)
    return AlertSearcher(
        helper=OpenCTIConnectorHelper(),
        opensearch=OpenSearchClient(config=osConf()),
        config=SearchConfig(**kwargs),
    )


@pytest.fixture
def mock_search(monkeypatch):
    def return_input(*args, **kwargs):
        return {"must": args[1], **kwargs} if len(args) > 1 else kwargs

    monkeypatch.setattr(OpenSearchClient, "search", return_input)


def random_filename():
    random.choice([f"name{i}" for i in range(1, 11)])


def random_sep():
    return random.choice(["/", "\\"])


def random_path():
    return f"foo{random_sep()}/{random_filename()}"


def random_abs_path():
    return random.choice(["/", "C:\\"]) + random_path()


# def random_path_names(*, path:bool, abs:bool):
#    return


def test_opensearch_mock(mock_search):
    c = OpenSearchClient(
        config=OpenSearchConfig(
            url=AnyHttpUrl("http://foo.bar"), username="foo", password="bar"
        )
    )

    result = c.search(must=[Term(field="foo", value="bar")])

    assert result == {
        "must": [Term(field="foo", value="bar", case_insensitive=False, boost=1.0)]
    }


def test_artifact_without_hash_none(caplog, monkeypatch, mock_search):
    caplog.set_level(logging.DEBUG, logger="wazuh.search")
    s = searcher(
        monkeypatch,
    )
    result = s.query_file(entity={"entity_type": "Artifact"}, stix_entity={})
    assert result is None

    messages = [record.msg for record in caplog.records]
    assert messages == [
        "Does file/Artifact have a hash: False",
        "Artifact does not have any hashes",
    ]


# one name
# multiple names
# random: path in name
# random: path is full path
#


def test_artifact_with_hashes(monkeypatch, mock_search):
    s = searcher(
        monkeypatch,
        filesearch_options={
            FileSearchOption.SearchSize,
            FileSearchOption.IncludeParentDirRef,
            FileSearchOption.IncludeRegValues,
            FileSearchOption.SearchFilenameOnly,
            FileSearchOption.AllowRegexp,
            FileSearchOption.CaseInsensitive,
        },
    )
    entity = {"entity_type": "Artifact"}
    stix = {"hashes": {"SHA-256": "sha256foo", "MD5": "md5bar"}}
    result = s.query_file(entity=entity, stix_entity=stix)
    assert result == {
        "should": [
            MultiMatch(query="sha256foo", fields=["*sha256*"]),
            MultiMatch(query="md5bar", fields=["*md5*"]),
        ]
    }


def test_file_hashes(monkeypatch, mock_search):
    s = searcher(
        monkeypatch,
    )
    entity = {"entity_type": "StixFile"}
    stix = {"hashes": {"SHA-256": "sha256foo", "MD5": "md5bar"}}
    result = s.query_file(entity=entity, stix_entity=stix)
    assert result == {
        "must": [
            Bool(
                should=[
                    MultiMatch(query="sha256foo", fields=["*sha256*"]),
                    MultiMatch(query="md5bar", fields=["*md5*"]),
                ],
            )
        ],
        "should": [],
    }


def test_no_hash_no_filenameonly_opt(caplog, monkeypatch, mock_search):
    caplog.set_level(logging.INFO, logger="wazuh.search")
    s = searcher(
        monkeypatch,
        # Remove SearchFilenameOnly:
        filesearch_options=set(),
    )
    entity = {"entity_type": "StixFile"}
    stix = {"name": "foo"}
    result = s.query_file(entity=entity, stix_entity=stix)
    assert result is None

    messages = [record.msg for record in caplog.records]
    assert messages == [
        "Observable has no hashes and SearchFilenameOnly is disabled",
    ]


def test_no_hash_no_filename(caplog, monkeypatch, mock_search):
    caplog.set_level(logging.INFO, logger="wazuh.search")
    s = searcher(
        monkeypatch,
    )
    entity = {"entity_type": "StixFile"}
    stix = {}
    result = s.query_file(entity=entity, stix_entity=stix)
    assert result is None

    messages = [record.msg for record in caplog.records]
    assert messages == [
        "Observable has no hashes and no file names",
    ]


def test_no_hash_filename_size(caplog, monkeypatch, mock_search):
    caplog.set_level(logging.INFO, logger="wazuh.search")
    s = searcher(
        monkeypatch,
    )
    entity = {"entity_type": "StixFile"}
    stix = {"name": "foo", "size": 42}
    result = s.query_file(entity=entity, stix_entity=stix)
    assert result == {
        "must": [
            MultiMatch(query="42", fields=["syscheck.size*"]),
        ],
        "should": [
            Regexp(field=field, query="(.*[/\\\\])?foo", case_insensitive=True)
            for field in fields
        ],
    }

    messages = [record.msg for record in caplog.records]
    assert messages == []


def test_no_hash_filename_size_no_case(caplog, monkeypatch, mock_search):
    caplog.set_level(logging.DEBUG, logger="wazuh.search")
    s = searcher(
        monkeypatch,
    )
    s.config.filesearch_options.remove(FileSearchOption.CaseInsensitive)
    entity = {"entity_type": "StixFile"}
    stix = {"name": "foo", "size": 42}
    result = s.query_file(entity=entity, stix_entity=stix)
    assert result == {
        "must": [
            MultiMatch(query="42", fields=["syscheck.size*"]),
        ],
        "should": [
            Regexp(field=field, query="(.*[/\\\\])?foo", case_insensitive=False)
            for field in fields
        ],
    }

    messages = [record.msg for record in caplog.records]
    assert messages == [
        "Does file/Artifact have a hash: False",
        "File filenames: ['foo']",
        "File parent path: None",
        "File size: 42",
        "File paths: ['foo']",
    ]


def test_no_hash_filename_size_no_abs(caplog, monkeypatch, mock_search):
    caplog.set_level(logging.DEBUG, logger="wazuh.search")
    s = searcher(
        monkeypatch,
    )
    s.config.filesearch_options.add(FileSearchOption.RequireAbsPath)
    entity = {"entity_type": "StixFile"}
    stix = {"name": "foo", "size": 42}
    result = s.query_file(entity=entity, stix_entity=stix)
    assert result is None

    messages = [record.msg for record in caplog.records]
    assert messages == [
        "Does file/Artifact have a hash: False",
        "File filenames: ['foo']",
        "File parent path: None",
        "File size: 42",
        "File paths: ['foo']",
        "RequireAbsPath is set and no paths are absolute",
    ]


def test_no_hash_filename_size_no_abs_no_regexp(caplog, monkeypatch, mock_search):
    caplog.set_level(logging.DEBUG, logger="wazuh.search")
    s = searcher(
        monkeypatch,
    )
    s.config.filesearch_options.remove(FileSearchOption.AllowRegexp)
    s.config.filesearch_options.add(FileSearchOption.RequireAbsPath)
    entity = {"entity_type": "StixFile"}
    stix = {"name": "foo", "size": 42}
    result = s.query_file(entity=entity, stix_entity=stix)
    assert result is None

    messages = [record.msg for record in caplog.records]
    assert messages == [
        "Does file/Artifact have a hash: False",
        "File filenames: ['foo']",
        "File parent path: None",
        "File size: 42",
        "File paths: ['foo']",
        "Not allowed to use regexp",
        "Absolute paths: []",
        "RequireAbsPath is set, Regexp is not allowed and no paths are absolute",
    ]


def test_no_hash_filename_size_no_regexp_no_abs(caplog, monkeypatch, mock_search):
    caplog.set_level(logging.DEBUG, logger="wazuh.search")
    s = searcher(
        monkeypatch,
    )
    s.config.filesearch_options.remove(FileSearchOption.AllowRegexp)
    entity = {"entity_type": "StixFile"}
    stix = {"name": "foo", "size": 42}
    result = s.query_file(entity=entity, stix_entity=stix)
    assert result is None

    messages = [record.msg for record in caplog.records]
    assert messages == [
        "Does file/Artifact have a hash: False",
        "File filenames: ['foo']",
        "File parent path: None",
        "File size: 42",
        "File paths: ['foo']",
        "Not allowed to use regexp",
        "Absolute paths: []",
        "Regexp is not allowed, and no paths are absolute",
    ]


def test_no_hash_filename_size_no_regexp_abs(caplog, monkeypatch, mock_search):
    caplog.set_level(logging.DEBUG, logger="wazuh.search")
    s = searcher(
        monkeypatch,
    )
    s.config.filesearch_options.remove(FileSearchOption.AllowRegexp)
    entity = {"entity_type": "StixFile"}
    stix = {"name": "/foo/bar", "size": 42}
    result = s.query_file(entity=entity, stix_entity=stix)
    assert result == {
        "must": [
            MultiMatch(query="42", fields=["syscheck.size*"]),
        ],
        "should": [
            MultiMatch(query="/foo/bar", fields=fields),
        ],
    }

    messages = [record.msg for record in caplog.records]
    assert messages == [
        "Does file/Artifact have a hash: False",
        "File filenames: ['/foo/bar']",
        "File parent path: None",
        "File size: 42",
        "File paths: ['/foo/bar']",
        "Not allowed to use regexp",
        "Absolute paths: ['/foo/bar']",
    ]


def test_hash_filename_size_no_regexp_abs(caplog, monkeypatch, mock_search):
    caplog.set_level(logging.DEBUG, logger="wazuh.search")
    s = searcher(
        monkeypatch,
    )
    s.config.filesearch_options.remove(FileSearchOption.AllowRegexp)
    entity = {"entity_type": "StixFile"}
    stix = {
        "name": "/foo/bar",
        "size": 42,
        "hashes": {"SHA-256": "foosha", "MD5": "foomd5", "SHA-1": "foosha1"},
    }
    result = s.query_file(entity=entity, stix_entity=stix)
    assert result == {
        "must": [
            Bool(
                should=[
                    MultiMatch(query="foosha", fields=["*sha256*"]),
                    MultiMatch(query="foomd5", fields=["*md5*"]),
                    MultiMatch(query="foosha1", fields=["*sha1*"]),
                ]
            ),
        ],
        "should": [],
    }

    messages = [record.msg for record in caplog.records]
    assert messages == [
        "Does file/Artifact have a hash: True",
        "File filenames: ['/foo/bar']",
        "File parent path: None",
        "File size: 42",
        "File paths: ['/foo/bar']",
    ]


def test_hash_filename_size_no_regexp_abs_name_and_hash(
    caplog, monkeypatch, mock_search
):
    caplog.set_level(logging.DEBUG, logger="wazuh.search")
    s = searcher(
        monkeypatch,
    )
    s.config.filesearch_options.add(FileSearchOption.SearchNameAndHash)
    s.config.filesearch_options.remove(FileSearchOption.AllowRegexp)
    entity = {"entity_type": "StixFile"}
    stix = {
        "name": "/foo/bar",
        "size": 42,
        "hashes": {"SHA-256": "foosha", "MD5": "foomd5", "SHA-1": "foosha1"},
    }
    result = s.query_file(entity=entity, stix_entity=stix)
    assert result == {
        "must": [
            Bool(
                should=[
                    MultiMatch(query="foosha", fields=["*sha256*"]),
                    MultiMatch(query="foomd5", fields=["*md5*"]),
                    MultiMatch(query="foosha1", fields=["*sha1*"]),
                ],
            ),
        ],
        "should": [
            MultiMatch(query="/foo/bar", fields=fields),
        ],
    }

    messages = [record.msg for record in caplog.records]
    assert messages == [
        "Does file/Artifact have a hash: True",
        "File filenames: ['/foo/bar']",
        "File parent path: None",
        "File size: 42",
        "File paths: ['/foo/bar']",
        "Not allowed to use regexp",
        "Absolute paths: ['/foo/bar']",
    ]


def test_hash_filename_size_regexp_abs_name_and_hash(caplog, monkeypatch, mock_search):
    caplog.set_level(logging.DEBUG, logger="wazuh.search")
    s = searcher(
        monkeypatch,
    )
    s.config.filesearch_options.add(FileSearchOption.SearchNameAndHash)
    entity = {"entity_type": "StixFile"}
    stix = {
        "name": "/foo/bar",
        "size": 42,
        "hashes": {"SHA-256": "foosha", "MD5": "foomd5", "SHA-1": "foosha1"},
    }
    result = s.query_file(entity=entity, stix_entity=stix)
    assert result == {
        "must": [
            Bool(
                should=[
                    MultiMatch(query="foosha", fields=["*sha256*"]),
                    MultiMatch(query="foomd5", fields=["*md5*"]),
                    MultiMatch(query="foosha1", fields=["*sha1*"]),
                ],
            )
        ],
        "should": [
            Regexp(query="/foo/bar", field=field, case_insensitive=True)
            for field in fields
        ],
    }

    messages = [record.msg for record in caplog.records]
    assert messages == [
        "Does file/Artifact have a hash: True",
        "File filenames: ['/foo/bar']",
        "File parent path: None",
        "File size: 42",
        "File paths: ['/foo/bar']",
    ]


def test_hash_filename_size_regexp_abs_name_winstyle(caplog, monkeypatch, mock_search):
    caplog.set_level(logging.DEBUG, logger="wazuh.search")
    s = searcher(
        monkeypatch,
    )
    entity = {"entity_type": "StixFile"}
    stix = {
        # TODO: make test consistent (set usage):
        # "name": "C:\\foo\\bar",
        "x_opencti_additional_names": ["C:\\\\bar\\\\\\\\baz"],
        "size": 42,
    }
    result = s.query_file(entity=entity, stix_entity=stix)
    assert result == {
        "must": [
            MultiMatch(query="42", fields=["syscheck.size*"]),
        ],
        "should": [
            Regexp(
                query="C:\\\\+bar\\\\+baz",
                field=field,
                case_insensitive=True,
            )
            for field in fields
        ],
    }

    messages = [record.msg for record in caplog.records]
    assert messages == [
        "Does file/Artifact have a hash: False",
        "File filenames: ['C:\\\\\\\\bar\\\\\\\\\\\\\\\\baz']",
        "File parent path: None",
        "File size: 42",
        "File paths: ['C:\\\\\\\\bar\\\\\\\\\\\\\\\\baz']",
    ]
