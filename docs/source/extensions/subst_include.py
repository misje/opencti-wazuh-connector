from docutils.parsers.rst import directives
from functools import wraps
from sphinx.application import Sphinx
from sphinx.directives.code import LiteralInclude, LiteralIncludeReader


def substitute(lines: list[str], subst: dict[str, str]) -> None:
    for i, line in enumerate(lines):
        for old, new in subst.items():
            line = line.replace(old, new)

        lines[i] = line


def subst_decorator(func):
    @wraps(func)
    def inner(self, *args, **kwargs):
        nonlocal func
        lines = func(self, *args, **kwargs)
        if "_subst_conf" in self.options:
            substitute(lines, self.options["_subst_conf"].substitutions)

        return lines

    return inner


LiteralIncludeReader.read_file = subst_decorator(LiteralIncludeReader.read_file)


class SubstLiteralInclude(LiteralInclude):
    def run(self):
        self.options["_subst_conf"] = self.config
        return super().run()


def setup(app: Sphinx) -> dict:  # ExtensionMetadata not available yet
    app.add_config_value("substitutions", {}, "html")
    app.add_directive("subst_literalinclude", SubstLiteralInclude)

    return {
        "version": "0.1.0",
        "parallel_read_safe": True,
        "parallel_write_safe": True,
    }
