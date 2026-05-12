import pytest
from datetime import datetime, timezone, timedelta
from app.utils.helper import parse_host, is_cache_valid
from app.utils.cert_utils import map_cert_data_to_models
from app.models import Certificate

def test_parse_host():
    """Test extracting hostname from various URL formats."""
    assert parse_host("https://google.com") == "google.com"
    assert parse_host("http://example.com/path?query=1") == "example.com"
    assert parse_host("google.com") == "google.com"
    assert parse_host("sub.domain.co.uk") == "sub.domain.co.uk"

def test_is_cache_valid():
    """Test cache validation logic."""
    now = datetime.now(timezone.utc)
    
    # Valid cache (10 hours ago)
    recent_scan = now - timedelta(hours=10)
    assert is_cache_valid(recent_scan) is True
    
    # Invalid cache (25 hours ago)
    old_scan = now - timedelta(hours=25)
    assert is_cache_valid(old_scan) is False
    
    # No scan time
    assert is_cache_valid(None) is False

def test_map_cert_data_to_models():
    """Test mapping raw dictionary data to SQLAlchemy models."""
    mock_data = {
        "certificate": {
            "serial_number": "ABC123",
            "subject": {"common_name": "example.com", "organization": "Org", "country": "US"},
            "issuer": {"common_name": "Issuer CA", "organization": "Issuer Org", "country": "US"},
            "validity": {
                "not_before": "2026-01-01T00:00:00+00:00",
                "not_after": "2027-01-01T00:00:00+00:00",
                "days_left": 365
            },
            "subject_alt_names": ["example.com", "www.example.com"]
        },
        "tls": {
            "version": "TLSv1.3",
            "cipher_suite": "TLS_AES_256_GCM_SHA384",
            "cipher_protocol": "TLSv1.3",
            "secret_bits": 256
        },
        "certificate_chain": [
            {
                "position": 0,
                "serial_number": "ROOT123",
                "subject": {"common_name": "Root CA", "organization": "Root Org", "country": "US"},
                "issuer": {"common_name": "Root CA", "organization": "Root Org", "country": "US"},
                "not_before": "2020-01-01T00:00:00+00:00",
                "not_after": "2030-01-01T00:00:00+00:00",
                "days_left": 3650
            }
        ],
        "security_checks": {
            "is_expired": False,
            "expires_soon": False,
            "strong_tls": True
        }
    }
    
    cert = map_cert_data_to_models(mock_data)
    
    # Verify core fields
    assert cert.serial_number == "ABC123"
    assert cert.subject_common_name == "example.com"
    assert cert.not_after == datetime(2027, 1, 1, tzinfo=timezone.utc)
    
    # Verify relationships
    assert len(cert.sans) == 2
    assert cert.sans[0].san_value == "example.com"
    
    assert cert.tls_detail.tls_version == "TLSv1.3"
    
    assert len(cert.chain_entries) == 1
    assert cert.chain_entries[0].serial_number == "ROOT123"
    
    assert cert.security_check.strong_tls is True
    assert cert.security_check.expires_soon is False

def test_map_cert_data_update_existing():
    """Test updating an existing certificate model with new data."""
    existing_cert = Certificate(
        serial_number="ABC123",
        subject_common_name="old.com"
    )
    
    mock_data = {
        "certificate": {
            "serial_number": "ABC123",
            "subject": {"common_name": "new.com"},
            "issuer": {},
            "validity": {
                "not_before": "2026-01-01T00:00:00+00:00",
                "not_after": "2027-01-01T00:00:00+00:00",
                "days_left": 100
            },
            "subject_alt_names": ["new.com"]
        },
        "certificate_chain": []
    }
    
    updated_cert = map_cert_data_to_models(mock_data, cert=existing_cert)
    
    assert updated_cert.serial_number == "ABC123"
    # Note: Our current map logic only updates days_left and not_after for existing certs
    assert updated_cert.days_left == 100
    assert len(updated_cert.sans) == 1
