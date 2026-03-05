"""Sample eCX API response payloads for testing.

Provides factory functions that return representative eCX API response
dicts (camelCase, as returned by the live API) for all four modules.
Use these as ``httpx.Response`` mock data or as arguments to Pydantic
model constructors (after key normalisation).
"""

from __future__ import annotations

from typing import Any


def phish_search_response(*, count: int = 1) -> dict[str, Any]:
    """Return a sample /phish/search response.

    Args:
        count: Number of phish records to include (max 3).
    """
    records = [
        {
            "id": 42,
            "url": "https://fake-bank.example.com/login",
            "brand": "ExampleBank",
            "confidence": 90,
            "status": "active",
            "discoveredAt": 1700000000,
            "createdAt": 1700000001,
            "updatedAt": 1700000002,
            "ip": ["1.2.3.4"],
            "asn": [12345],
            "tld": "com",
        },
        {
            "id": 43,
            "url": "https://fake-bank.example.com/verify",
            "brand": "ExampleBank",
            "confidence": 85,
            "status": "active",
            "discoveredAt": 1700001000,
            "createdAt": 1700001001,
            "ip": ["1.2.3.4"],
            "asn": [12345],
            "tld": "com",
        },
        {
            "id": 44,
            "url": "https://another-scam.example.org/",
            "brand": "AnotherBrand",
            "confidence": 70,
            "status": "inactive",
            "discoveredAt": 1699999000,
            "createdAt": 1699999001,
            "ip": ["5.6.7.8"],
            "asn": [67890],
            "tld": "org",
        },
    ]
    return {"data": records[:count]}


def domain_search_response(*, count: int = 1) -> dict[str, Any]:
    """Return a sample /malicious-domain/search response."""
    records = [
        {
            "id": 101,
            "domain": "fake-bank.example.com",
            "classification": "phishing",
            "confidence": 85,
            "status": "active",
            "discoveredAt": 1700000000,
        },
        {
            "id": 102,
            "domain": "evil-store.example.net",
            "classification": "fraud",
            "confidence": 75,
            "status": "active",
            "discoveredAt": 1700002000,
        },
    ]
    return {"data": records[:count]}


def ip_search_response(*, count: int = 1) -> dict[str, Any]:
    """Return a sample /malicious-ip/search response."""
    records = [
        {
            "id": 201,
            "ip": "1.2.3.4",
            "brand": "ExampleBank",
            "description": "Phish hosting server",
            "confidence": 80,
            "status": "active",
            "asn": [12345],
            "port": 443,
            "discoveredAt": 1700000000,
        },
    ]
    return {"data": records[:count]}


def crypto_search_response(*, count: int = 1) -> dict[str, Any]:
    """Return a sample /cryptocurrency-addresses/search response."""
    records = [
        {
            "id": 301,
            "currency": "bitcoin",
            "address": "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",
            "crimeCategory": "fraud",
            "siteLink": "https://scam.example.com",
            "price": 0,
            "source": "community",
            "procedure": "manual",
            "actorCategory": "pig-butchering",
            "confidence": 95,
            "status": "active",
            "discoveredAt": 1700000000,
        },
        {
            "id": 302,
            "currency": "ethereum",
            "address": "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD0E",
            "crimeCategory": "investment_fraud",
            "siteLink": "https://scam2.example.com",
            "price": 0,
            "source": "law_enforcement",
            "procedure": "automated",
            "actorCategory": "romance-scam",
            "confidence": 88,
            "status": "active",
            "discoveredAt": 1700005000,
        },
    ]
    return {"data": records[:count]}


def report_phishing_response(*, count: int = 1) -> dict[str, Any]:
    """Return a sample /report-phishing/search response."""
    records = [
        {
            "id": 501,
            "emailSubject": "Urgent: Verify your account",
            "senderEmail": "security@fake-bank.example.com",
            "emailBody": "Click https://fake-bank.example.com/login to verify.",
            "createdAt": 1700000000,
        },
    ]
    return {"data": records[:count]}
