import importlib
import py
import pytest
import re
import yaml


def pytest_collect_file(parent, path):
    """pytest hook to load YAML files as parametrized challenge tests."""
    match = re.search('test/(set\d)/(challenge_\d\d)\.yaml', str(path))

    if match is not None:
        challenge_set, challenge_num = match.group(1), match.group(2)

        return CryptopalsYamlFile(challenge_set, challenge_num, path, parent)


class CryptopalsYamlFile(pytest.File):
    """ pytest collection class for testing challenges with YAML files. """

    def __init__(self, challenge_set, challenge_num, path, parent):
        super(CryptopalsYamlFile, self).__init__(path, parent)

        self.challenge_set = challenge_set
        self.challenge_num = challenge_num
        self.module_name = 'cryptopals.%s.%s' % (challenge_set, challenge_num)

        self.module = importlib.import_module(self.module_name)

        # Make sure the module has a test attribute that is callable
        assert getattr(self.module, 'test')
        assert getattr(self.module.test, '__call__')

    def collect(self):
        """Load every document in the YAML file as a seperate test."""
        test_runs = yaml.safe_load_all(self.fspath.open())

        for run, params in enumerate(test_runs):
            name = "%s [%d]" % (self.module_name, run)

            yield CryptopalsChallengeTest(name, self, self.module, params)


class CryptopalsChallengeTest(pytest.Item):
    """pytest Item class for testing a single challenge."""

    def __init__(self, name, parent, module, params):
        super(CryptopalsChallengeTest, self).__init__(name, parent)

        self.module = module
        self.params = params

    def runtest(self):
        """Calls the (assumed to exist) test function on the module."""
        self.module.test(**self.params)

    def reportinfo(self):
        return self.fspath, None, self.name

    def _prunetraceback(self, excinfo):
        """Removes unecessary traceback information for presenting a test
        failure. Heavily inspired by the same function in the native _pytest
        plugin."""
        if self.config.option.fulltrace:
            # Do nothing, as we do not want to prune the traceback
            return

        # Get the test function metadata for filtering
        code = py.code.Code(self.module.test)
        path, firstlineno = code.path, code.firstlineno

        # Filter the traceback to only the bits regarding this test
        traceback = excinfo.traceback
        traceback = traceback.cut(path=path, firstlineno=firstlineno)
        traceback = traceback.filter()

        excinfo.traceback = traceback

        if self.config.option.tbstyle == "auto":
            if len(excinfo.traceback) > 2:
                for entry in excinfo.traceback[1:-1]:
                    entry.set_repr_style('short')

    def _repr_failure_py(self, excinfo, style="long"):
        if excinfo.errisinstance(pytest.fail.Exception):
            if not excinfo.value.pytrace:
                return str(excinfo.value)

        return super(CryptopalsChallengeTest, self)._repr_failure_py(
            excinfo, style=style)

    def repr_failure(self, excinfo):
        style = self.config.option.tbstyle
        style = style if style != 'auto' else None

        return self._repr_failure_py(excinfo, style=style)
