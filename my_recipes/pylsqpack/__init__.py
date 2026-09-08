from pythonforandroid.recipe import CythonRecipe


class PylsqpackRecipe(CythonRecipe):
    name = "pylsqpack"
    version = "0.3.18"
    url = "https://pypi.python.org/packages/source/p/pylsqpack/pylsqpack-{version}.tar.gz"
    depends = []
    call_hostpython_via_targetpython = False
    install_in_hostpython = False


recipe = PylsqpackRecipe()
