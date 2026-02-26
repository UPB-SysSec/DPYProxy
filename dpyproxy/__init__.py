# Entry-point for `dpyproxy = "dpyproxy:main"` in console_scripts.
#
# main.py lives at the repo root and is installed into site-packages as a
# top-level module (via [tool.hatch.build.targets.wheel] include = ["main.py"]).
# The sibling packages (enumerators/, exception/, modules/, network/, util/)
# are also installed as top-level packages, so all imports inside main.py
# resolve correctly at runtime.

from main import main  # noqa: F401
