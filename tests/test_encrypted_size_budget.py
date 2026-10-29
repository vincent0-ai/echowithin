"""Regression tests for the encrypted-upload size budget.

Cloudinary caps the ENCRYPTED payload (10MB on the free plan) while media is
encrypted with Fernet, which inflates data by ~33%. Compressing a video to the
cap as if it were plaintext therefore guarantees rejection — this bit us with
12.4MB uploads failing after minutes of FFmpeg work.
"""
import pytest
from cryptography.fernet import Fernet

from security import encrypted_size_for, max_plaintext_for_encrypted_limit

CLOUDINARY_CAP = 10 * 1024 * 1024


@pytest.fixture(scope="module")
def fernet():
    return Fernet(Fernet.generate_key())


class TestEncryptedSizeFormula:
    """The size model must match cryptography's real output exactly."""

    @pytest.mark.parametrize("plaintext_size", [
        1, 15, 16, 17, 31, 32, 33, 47, 48, 63,
        1_000, 100_000, 1_000_000, 8_000_000,
    ])
    def test_matches_real_fernet_output(self, fernet, plaintext_size):
        actual = len(fernet.encrypt(b"x" * plaintext_size))
        assert encrypted_size_for(plaintext_size) == actual

    def test_zero_and_negative_are_zero(self):
        assert encrypted_size_for(0) == 0
        assert encrypted_size_for(-5) == 0

    def test_encryption_expands_by_about_a_third(self):
        size = 10 * 1024 * 1024
        assert encrypted_size_for(size) == pytest.approx(size * 4 / 3, rel=0.01)


class TestPlaintextBudget:
    """max_plaintext_for_encrypted_limit must produce a value that actually fits."""

    def test_budget_fits_after_encryption(self, fernet):
        budget = max_plaintext_for_encrypted_limit(CLOUDINARY_CAP)
        assert budget > 0
        assert len(fernet.encrypt(b"x" * budget)) <= CLOUDINARY_CAP

    def test_budget_is_maximal(self, fernet):
        budget = max_plaintext_for_encrypted_limit(CLOUDINARY_CAP)
        assert len(fernet.encrypt(b"x" * (budget + 1))) > CLOUDINARY_CAP

    def test_budget_is_well_under_the_cap(self):
        """The whole point: the plaintext budget is notably smaller than the cap."""
        budget = max_plaintext_for_encrypted_limit(CLOUDINARY_CAP)
        assert budget < CLOUDINARY_CAP * 0.8

    def test_old_behaviour_would_have_overflowed(self, fernet):
        """Guard against regressing to 'compress to the cap itself'."""
        encrypted = len(fernet.encrypt(b"x" * CLOUDINARY_CAP))
        assert encrypted > CLOUDINARY_CAP

    @pytest.mark.parametrize("limit", [0, -1, 50])
    def test_degenerate_limits_return_zero(self, limit):
        """Caps too small to hold even one encrypted block yield no budget."""
        assert max_plaintext_for_encrypted_limit(limit) == 0

    def test_small_but_workable_limit(self, fernet):
        budget = max_plaintext_for_encrypted_limit(100)
        assert budget > 0
        assert len(fernet.encrypt(b"x" * budget)) <= 100
