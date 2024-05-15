import os
import sys

# -- Project information -----------------------------------------------------
project = "opencti-wazuh-connector"
copyright = "2024, Andreas Misje"  # pylint: disable=redefined-builtin
author = "Andreas Misje"
release = "0.1.0"
## The full version, including alpha/beta/rc tags
# with open("../../../version.txt", "r") as f:
#    release = f.readline().rstrip()

# -- General configuration ---------------------------------------------------
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
]
# Sjekk ut autosummary

templates_path = ["_templates"]
exclude_patterns = []

add_module_names = False
pygments_style = "sphinx"

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
    "octiu": ("https://docs.opencti.io/6.1.X/usage/%s", "OpenCTI usage documentation"),
    "octia": (
        "https://docs.opencti.io/6.1.X/administration/%s",
        "OpenCTI administration documentation",
    ),
    "octid": (
        "https://docs.opencti.io/6.1.X/deployment/%s",
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
