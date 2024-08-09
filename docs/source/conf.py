import json
import os
import subprocess
import sys

# -- Project information -----------------------------------------------------
project = "opencti-wazuh-connector"
copyright = "2024, Andreas Misje"  # pylint: disable=redefined-builtin
author = "Andreas Misje"
# Get latest release version from the last git tag on the current branch:
release = os.getenv(
    "CONNECTOR_RELEASE",
    subprocess.run(
        ["git", "describe", "--tags", "--abbrev=0"], capture_output=True, text=True
    ).stdout.rstrip(),
)

# -- misc. ---------- --------------------------------------------------------
# Generate table of "compatible" OpenCTI versions:
with open("prev_opencti_versions", "r", encoding="utf-8") as rst_in, open(
    "current_opencti_versions.rst", "w", encoding="utf-8"
) as rst_out, open("../../build_metadata.json", "r", encoding="utf-8") as build_meta:
    octi_versions = sorted(json.load(build_meta)["opencti_version"])
    latest_octi_version = octi_versions[-1]
    for line in rst_in:
        rst_out.write(line)

    release_link = "https://github.com/OpenCTI-Platform/opencti/releases/tag/"
    rst_out.write(f"   * - {release}\n")
    rst_out.write(
        "     - "
        + ", ".join([f"`{ver} <{release_link}{ver}>`_" for ver in octi_versions])
        + "\n\n"
    )

# -- General configuration ---------------------------------------------------
sys.path.insert(0, os.path.abspath("extensions"))
extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.doctest",
    "sphinx.ext.coverage",
    "sphinx.ext.extlinks",
    "sphinx_paramlinks",
    # Include when project published:
    # "sphinx.ext.viewcode",
    "sphinx_rtd_theme",
    "sphinxcontrib.autodoc_pydantic",
    "sphinxcontrib.mermaid",
    "subst_include",
]
# Sjekk ut autosummary

templates_path = ["_templates"]
exclude_patterns = []

add_module_names = False
pygments_style = "sphinx"

# TODO: replace minion, redis etc. versions in opencti-compose.yml
# Used by the custom integration subst_include:
substitutions = {
    "|latest|": f"{release}_{latest_octi_version}",
    "|latest_octi_ver|": latest_octi_version,
}
# General substitutions using epilog:
rst_epilog = "\n".join(
    (f".. {key} replace:: {value}" for key, value in substitutions.items())
)

# -- Options for HTML output -------------------------------------------------
html_theme = "sphinx_rtd_theme"

# GitHub integration
html_context = {
    "display_github": True,
    "github_user": "misje",
    "github_repo": "opencti-wazuh-connector",
    "github_version": "dev",
    "conf_py_path": "/docs/source/",
}

# -- autodoc options ---------------------------------------------------------
autodoc_member_order = "bysource"
# Enable these in developer doc. with directives if needed:
autodoc_pydantic_settings_show_validator_members = False
autodoc_pydantic_settings_show_validator_summary = False
autodoc_pydantic_settings_show_json = False
autodoc_pydantic_model_show_json_error_strategy = "coerce"

# -- extlinks options --------------------------------------------------------
extlinks = {
    "octiu": ("https://docs.opencti.io/6.2.X/usage/%s", "OpenCTI usage documentation"),
    "octia": (
        "https://docs.opencti.io/6.2.X/administration/%s",
        "OpenCTI administration documentation",
    ),
    "octid": (
        "https://docs.opencti.io/6.2.X/deployment/%s",
        "OpenCTI deployment documentation",
    ),
    "octigh": (
        "https://github.com/OpenCTI-Platform/%s",
        "OpenCTI's GitHub pages",
    ),
    "wazuh": (
        "https://documentation.wazuh.com/current/user-manual/%s",
        "Wazuh user documentation",
    ),
    "stix": (
        "https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html%s",
        "STIX 2.1 reference",
    ),
    "ghconnector": (
        "https://github.com/OpenCTI-Platform/connectors/tree/master/%s",
        "OpenCTI connectors on GitHub",
    ),
    "dsl": (
        "https://opensearch.org/docs/latest/query-dsl/%s",
        "OpenSearch DSL query reference",
    ),
    "pydantic": ("https://docs.pydantic.dev/2.7/%s", "Pydantic documentation"),
    "github": (
        "https://github.com/misje/opencti-wazuh-connector/%s",
        "Project's GitHub page",
    ),
    "dcompose": (
        "https://docs.docker.com/compose/compose-file/05-services/#%s",
        "docker-compose reference",
    ),
}

sys.path.insert(0, os.path.abspath("../../src"))
