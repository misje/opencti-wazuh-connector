import os
import sys

# -- Project information -----------------------------------------------------
project = "opencti-wazuh-connector"
copyright = "2024, Andreas Misje"
author = "Andreas Misje"
release = "0.0.1"
## The full version, including alpha/beta/rc tags
# with open("../../../version.txt", "r") as f:
#    release = f.readline().rstrip()

# -- General configuration ---------------------------------------------------
extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.doctest",
    "sphinx.ext.coverage",
    "sphinx.ext.extlinks",
    # Include when project published:
    # "sphinx.ext.viewcode",
    "sphinx_rtd_theme",
    "sphinxcontrib.autodoc_pydantic",
]
# Sjekk ut autosummary

templates_path = ["_templates"]
exclude_patterns = []

add_module_names = False
pygments_style = "sphinx"

# -- Options for HTML output -------------------------------------------------
html_theme = "sphinx_rtd_theme"
html_static_path = ["_static"]

# GitHub integration
html_context = {
    "display_github": True,
    "github_user": "misje",
    "github_repo": "opencti-wazuh",
    "github_version": "master",
    "conf_py_path": "/docs/source/",
}

# -- autodoc options ---------------------------------------------------------
autodoc_member_order = "bysource"
# autodoc_pydantic_model_show_field_summary = False
# autodoc_pydantic_field_signature_prefix = ' '
# autodoc_pydantic_model_signature_prefix = 'class'
# autodoc_pydantic_model_show_json = False
# autodoc_pydantic_model_show_config_summary = False
# autodoc_pydantic_model_show_config_member = False
# autodoc_pydantic_model_show_validator_summary = False
# autodoc_pydantic_model_show_validator_members = False
# autodoc_pydantic_model_summary_list_order = 'bysource'
# autodoc_pydantic_model_member_order = 'bysource'
# autodoc_pydantic_field_list_validators = False

# -- extlinks options --------------------------------------------------------
extlinks = {
    "octiu": ("https://docs.opencti.io/latest/usage/%s", "OpenCTI usage documentation"),
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
}

# TODO: gloassary and :term:

sys.path.insert(0, os.path.abspath("../../src"))