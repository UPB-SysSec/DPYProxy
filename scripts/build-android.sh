#!/usr/bin/env bash
# Runs buildozer with the Android (Kivy) entry point in place.
#
# python-for-android's SDL2 bootstrap hardcodes the app entry point
# filename to "main.py" (see PythonActivity.java's getEntryPoint()) — there
# is no buildozer.spec option to change it. Since main.py in this repo is
# the desktop CLI entry point, android_main.py is swapped into main.py's
# place only for the duration of the build, then the real main.py is
# restored, even if the build fails.
#
# Usage: same arguments you'd pass to buildozer, e.g.
#   ./scripts/build-android.sh android debug deploy run logcat
set -euo pipefail
cd "$(dirname "$0")/.."

backup="$(mktemp)"
cp main.py "$backup"
trap 'mv "$backup" main.py' EXIT

cp android_main.py main.py
buildozer "$@"
