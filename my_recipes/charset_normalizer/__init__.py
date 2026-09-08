# charset_normalizer is a transitive dependency (pulled in by one of our
# requirements) that p4a would otherwise auto-resolve via `pip --dry-run`
# and pip-install on the host without cross-platform flags. The newest
# PyPI release ships a prebuilt Android wheel that step can't install
# ("... is not a supported wheel on this platform"), breaking every build
# regardless of buildozer.spec pins or VERSION_* env overrides — those only
# apply when a module is still a bare name at install time, but this one
# gets resolved to a specific wheel URL earlier. Declaring it as a recipe
# here (like the pylsqpack recipe next to this one) makes p4a install it
# through the recipe system instead, sidestepping that broken path entirely.
# It must also be listed explicitly in buildozer.spec's requirements (not
# just left to transitive resolution) for this recipe to be matched at all.
from pythonforandroid.recipe import PythonRecipe


class CharsetNormalizerRecipe(PythonRecipe):
    name = "charset_normalizer"
    version = "3.3.2"
    url = "https://files.pythonhosted.org/packages/63/09/c1bc53dab74b1816a00d8d030de5bf98f724c52c1635e07681d312f20be8/charset-normalizer-{version}.tar.gz"
    depends = []
    call_hostpython_via_targetpython = False


recipe = CharsetNormalizerRecipe()
