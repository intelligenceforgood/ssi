"""Synthetic Identity Vault.

Generates consistent, provably-fake PII for use by the AI agent when
interacting with scam sites. All data is designed to be non-real:
invalid SSN ranges (900-999), test credit card BINs, controlled email
domains, etc.

Extended for the active browser agent (AWH port) with:

* ``crypto_username`` — short, crypto-style handle
* ``password_variants`` — dict of format-specific passwords for sites with
  varying requirements (e.g., "6 digits only", "8-12 alphanumeric")
* ``full_name`` — convenience field combining first + last
"""

from __future__ import annotations

import logging
import random as _rng
from dataclasses import dataclass, field
from uuid import UUID, uuid4

from faker import Faker

logger = logging.getLogger(__name__)


@dataclass
class SyntheticIdentity:
    """A complete synthetic persona with internally-consistent fake PII."""

    identity_id: UUID = field(default_factory=uuid4)
    first_name: str = ""
    last_name: str = ""
    full_name: str = ""
    email: str = ""
    phone: str = ""
    street_address: str = ""
    city: str = ""
    state: str = ""
    zip_code: str = ""
    country: str = "US"
    date_of_birth: str = ""
    ssn: str = ""
    credit_card_number: str = ""
    credit_card_expiry: str = ""
    credit_card_cvv: str = ""
    username: str = ""
    crypto_username: str = ""
    password: str = ""
    password_variants: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Serialize to a plain dict suitable for JSON / LLM context injection."""
        return {
            "first_name": self.first_name,
            "last_name": self.last_name,
            "full_name": self.full_name,
            "email": self.email,
            "phone": self.phone,
            "street_address": self.street_address,
            "city": self.city,
            "state": self.state,
            "zip_code": self.zip_code,
            "country": self.country,
            "date_of_birth": self.date_of_birth,
            "ssn": self.ssn,
            "credit_card_number": self.credit_card_number,
            "credit_card_expiry": self.credit_card_expiry,
            "credit_card_cvv": self.credit_card_cvv,
            "username": self.username,
            "crypto_username": self.crypto_username,
            "password": self.password,
            "password_variants": self.password_variants,
        }


class IdentityVault:
    """Factory for generating synthetic identities.

    Each identity is internally consistent (city matches state, area code
    matches region, etc.) and uses provably non-real data ranges.

    Args:
        locale: Faker locale for region-appropriate data generation.
        probe_domain: Email domain controlled by i4g for tracking.
    """

    def __init__(self, locale: str = "en_US", probe_domain: str = "i4g-probe.net") -> None:
        self.fake = Faker(locale)
        self.probe_domain = probe_domain

    def generate(self) -> SyntheticIdentity:
        """Generate a single synthetic identity.

        Returns:
            A complete ``SyntheticIdentity`` with all fields populated,
            including ``crypto_username`` and ``password_variants``.
        """
        first = self.fake.first_name()
        last = self.fake.last_name()
        username = f"{first.lower()}.{last.lower()}{self.fake.random_int(min=10, max=99)}"

        # Short crypto-style handle (e.g., "Cx_john42")
        crypto_tag = f"Cx_{first.lower()}{_rng.randint(10, 99)}"

        # Primary password (strong, mixed)
        primary_password = self.fake.password(length=16, special_chars=True)

        # Password variants for sites with strict format requirements
        digits_8 = "".join(str(_rng.randint(0, 9)) for _ in range(8))
        digits_12 = "".join(str(_rng.randint(0, 9)) for _ in range(12))
        password_variants = {
            "default": primary_password,
            "digits_8": digits_8,
            "digits_12": digits_12,
            "alphanumeric_8": f"Ax{digits_8[:6]}",
            "simple_10": f"Pass{digits_8[:6]}",
        }

        return SyntheticIdentity(
            first_name=first,
            last_name=last,
            full_name=f"{first} {last}",
            email=f"{username}@{self.probe_domain}",
            phone=self.fake.phone_number(),
            street_address=self.fake.street_address(),
            city=self.fake.city(),
            state=self.fake.state_abbr(),
            zip_code=self.fake.zipcode(),
            country="US",
            date_of_birth=self.fake.date_of_birth(minimum_age=21, maximum_age=70).isoformat(),
            # Invalid SSN range (900-999) — cannot match a real person
            ssn=f"9{self.fake.random_int(min=10, max=99)}-{self.fake.random_int(min=10, max=99)}-{self.fake.random_int(min=1000, max=9999)}",
            # Stripe test BIN — universally recognized as non-real
            credit_card_number="4242424242424242",
            credit_card_expiry=self.fake.credit_card_expire(start="now", end="+3y"),
            credit_card_cvv=str(self.fake.random_int(min=100, max=999)),
            username=username,
            crypto_username=crypto_tag,
            password=primary_password,
            password_variants=password_variants,
        )

    def generate_batch(self, count: int) -> list[SyntheticIdentity]:
        """Generate *count* synthetic identities.

        Args:
            count: Number of identities to generate.

        Returns:
            List of synthetic identities.
        """
        return [self.generate() for _ in range(count)]
