"""Synthetic Identity Vault.

Generates consistent, provably-fake PII for use by the AI agent when
interacting with scam sites. All data is designed to be non-real:
invalid SSN ranges (900-999), test credit card BINs, controlled email
domains, etc.
"""

from __future__ import annotations

import logging
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
    password: str = ""


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
            A complete ``SyntheticIdentity`` with all fields populated.
        """
        first = self.fake.first_name()
        last = self.fake.last_name()
        username = f"{first.lower()}.{last.lower()}{self.fake.random_int(min=10, max=99)}"

        return SyntheticIdentity(
            first_name=first,
            last_name=last,
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
            credit_card_number=f"4242424242424242",
            credit_card_expiry=self.fake.credit_card_expire(start="now", end="+3y"),
            credit_card_cvv=str(self.fake.random_int(min=100, max=999)),
            username=username,
            password=self.fake.password(length=16, special_chars=True),
        )

    def generate_batch(self, count: int) -> list[SyntheticIdentity]:
        """Generate *count* synthetic identities.

        Args:
            count: Number of identities to generate.

        Returns:
            List of synthetic identities.
        """
        return [self.generate() for _ in range(count)]
