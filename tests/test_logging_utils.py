"""Tests for common/logging_utils.py's setup_tool_logging() - the shared
console/file/syslog setup every tool (server.py, acme_server.py,
crtrequest.py, cltmanager.py, crtmanager.py, dbmigrate.py, admintui) now
calls, generalized from what used to be server.py-only setup_server_logging()
(see the 2026-09-20 issue.md entry this was written to close - logging was
previously handled differently/inconsistently, or not at all, by nearly
every tool in the project).

Since logging.getLogger("sslcrtsrv") is a process-wide singleton and
setup_tool_logging() is deliberately idempotent (a second call is a no-op),
every test here resets that logger's handlers/state in setUp()/tearDown() -
otherwise tests would observe whatever a previous test already configured,
not what they themselves are exercising.

Run with:
    python3 -m unittest discover -s tests -v
from the repository root (with the project installed, or PYTHONPATH=src set).
"""
import logging
import logging.handlers
import shutil
import tempfile
import unittest

from sslcrtsrv.common.logging_utils import (
    setup_tool_logging, setup_tool_logging_from_file, PACKAGE_LOGGER_NAME,
)


class LoggingUtilsTestCase(unittest.TestCase):
    def setUp(self):
        self.logger = logging.getLogger(PACKAGE_LOGGER_NAME)
        self._reset_logger()
        self.log_dir = tempfile.mkdtemp(prefix="logging-utils-test-")

    def tearDown(self):
        self._reset_logger()
        shutil.rmtree(self.log_dir, ignore_errors=True)

    def _reset_logger(self):
        for handler in list(self.logger.handlers):
            self.logger.removeHandler(handler)
            handler.close()
        self.logger.setLevel(logging.NOTSET)
        self.logger.propagate = True


class TestBasicSetup(LoggingUtilsTestCase):
    def test_console_and_file_handlers_attached_by_default(self):
        logger = setup_tool_logging({"log_dir": self.log_dir}, "testtool")
        types = {type(h) for h in logger.handlers}
        self.assertIn(logging.StreamHandler, types)
        self.assertTrue(any(isinstance(h, logging.handlers.RotatingFileHandler) for h in logger.handlers))
        self.assertFalse(logger.propagate)
        self.assertEqual(logger.level, logging.INFO)

    def test_console_false_skips_the_stream_handler(self):
        logger = setup_tool_logging({"log_dir": self.log_dir}, "testtool", console=False)
        self.assertFalse(any(type(h) is logging.StreamHandler for h in logger.handlers))
        self.assertTrue(any(isinstance(h, logging.handlers.RotatingFileHandler) for h in logger.handlers))

    def test_falsy_log_dir_disables_file_logging(self):
        logger = setup_tool_logging({"log_dir": ""}, "testtool")
        self.assertFalse(any(isinstance(h, logging.handlers.RotatingFileHandler) for h in logger.handlers))
        self.assertTrue(any(type(h) is logging.StreamHandler for h in logger.handlers))

    def test_log_file_actually_written_under_configured_dir(self):
        logger = setup_tool_logging({"log_dir": self.log_dir}, "testtool")
        logger.info("hello from testtool")
        for handler in logger.handlers:
            handler.flush()
        log_path = f"{self.log_dir}/testtool.log"
        with open(log_path) as f:
            content = f.read()
        self.assertIn("hello from testtool", content)

    def test_idempotent_second_call_does_not_duplicate_handlers(self):
        logger1 = setup_tool_logging({"log_dir": self.log_dir}, "testtool")
        handler_count = len(logger1.handlers)
        logger2 = setup_tool_logging({"log_dir": self.log_dir}, "othertool")
        self.assertIs(logger1, logger2)
        self.assertEqual(len(logger2.handlers), handler_count,
                          "a second call must be a no-op, not add more handlers")

    def test_unreachable_syslog_falls_back_without_raising(self):
        # A syslog_host that can't resolve - the probe must fail closed
        # (console/file still work) rather than raise or hang.
        logger = setup_tool_logging(
            {"log_dir": self.log_dir, "syslog_host": "this-host-does-not-resolve.invalid"}, "testtool")
        self.assertFalse(any(isinstance(h, logging.handlers.SysLogHandler) for h in logger.handlers))
        self.assertTrue(any(type(h) is logging.StreamHandler for h in logger.handlers))


class TestSetupFromFile(LoggingUtilsTestCase):
    def test_missing_file_falls_back_to_defaults(self):
        logger = setup_tool_logging_from_file("/nonexistent/path/server_config.json", "testtool")
        self.assertTrue(any(type(h) is logging.StreamHandler for h in logger.handlers))

    def test_invalid_json_falls_back_to_defaults(self):
        import os
        bad_path = os.path.join(self.log_dir, "bad_config.json")
        with open(bad_path, "w") as f:
            f.write("{not valid json")
        logger = setup_tool_logging_from_file(bad_path, "testtool")
        self.assertTrue(any(type(h) is logging.StreamHandler for h in logger.handlers))

    def test_console_kwarg_is_forwarded(self):
        import os
        import json
        config_path = os.path.join(self.log_dir, "config.json")
        with open(config_path, "w") as f:
            json.dump({"log_dir": self.log_dir}, f)
        logger = setup_tool_logging_from_file(config_path, "testtool", console=False)
        self.assertFalse(any(type(h) is logging.StreamHandler for h in logger.handlers))


class TestEntryPointLoggerNamesSurviveDashM(unittest.TestCase):
    """Regression test for a real bug caught live while verifying this
    feature: cltmanager.py/crtmanager.py/dbmigrate.py/crtrequest.py each
    initially used the ordinary logging.getLogger(__name__) idiom, exactly
    like server.py/acme_server.py's OWN sibling modules do - except those
    two are deliberately hardcoded instead (see their own inline comments),
    specifically because each is commonly run via
    `python3 -m sslcrtsrv.<module>`, under which __name__ becomes
    "__main__" for *that* module rather than "sslcrtsrv.<module>" - a
    logger named "__main__" is not a descendant of the shared "sslcrtsrv"
    ancestor logger setup_tool_logging() configures, so every
    logger.info()/.warning() call in that module would silently go nowhere
    (verified live: `python3 -m sslcrtsrv.dbmigrate upgrade-schema` ran
    correctly but its own log lines were completely absent from both
    console and the log file, with no error of any kind). This test can't
    reproduce the "run via -m" condition directly (unittest itself imports
    these modules normally), so it instead pins down the actual invariant
    that matters: each module's logger name must already be the correct,
    final "sslcrtsrv.<module>" string - not the fragile "whatever __name__
    happens to resolve to in this context" - so it stays correct regardless
    of how the module was loaded."""

    def test_cli_tool_loggers_use_explicit_names(self):
        from sslcrtsrv import cltmanager, crtmanager, dbmigrate, crtrequest
        expected = {
            cltmanager: "sslcrtsrv.cltmanager",
            crtmanager: "sslcrtsrv.crtmanager",
            dbmigrate: "sslcrtsrv.dbmigrate",
            crtrequest: "sslcrtsrv.crtrequest",
        }
        for module, expected_name in expected.items():
            with self.subTest(module=module.__name__):
                self.assertEqual(module.logger.name, expected_name)
                # And the real invariant that matters: it must actually be
                # a descendant of the ancestor setup_tool_logging() configures.
                self.assertTrue(module.logger.name.startswith(PACKAGE_LOGGER_NAME + "."))


if __name__ == "__main__":
    unittest.main()
