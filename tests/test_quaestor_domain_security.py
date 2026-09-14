import unittest

from deep_tests.security_model import BoundaryViolation, normalize_relative_path, validate_outbound_url


class QuaestorDomainSecurityTests(unittest.TestCase):
    def test_statement_export_paths_reject_encoded_escape(self) -> None:
        for value in ("exports/%2e%2e/secrets.csv", "statements/%252e%252e/key", "%2E%2E/ledger.sql"):
            with self.subTest(value=value), self.assertRaises(BoundaryViolation):
                normalize_relative_path(value)

    def test_ledger_webhook_urls_reject_authority_confusion(self) -> None:
        allowed = {"ledger.example.test"}
        for value in (
            "//ledger.example.test/webhook",
            "https://ledger.example.test@attacker.invalid/webhook",
            "https://attacker.invalid/ledger.example.test/webhook",
        ):
            with self.subTest(value=value), self.assertRaises(BoundaryViolation):
                validate_outbound_url(value, allowed)


if __name__ == "__main__":
    unittest.main()
