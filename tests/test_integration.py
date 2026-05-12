
from datetime import datetime, timezone
from app.models import Host, Certificate, CertificateScan
from app.utils.cert_utils import map_cert_data_to_models
from app.query_repo import QueryRepository as Repo

def test_full_certificate_storage_and_retrieval(db_session):
    """Integration test: Verify that a full certificate object graph is correctly saved and retrieved."""
    
    # 1. Setup mock data
    mock_data = {
        "certificate": {
            "serial_number": "INTTEST123",
            "subject": {"common_name": "integration.test", "organization": "Test Org", "country": "US"},
            "issuer": {"common_name": "Test CA", "organization": "CA Org", "country": "US"},
            "validity": {
                "not_before": "2026-01-01T00:00:00+00:00",
                "not_after": "2027-01-01T00:00:00+00:00",
                "days_left": 365
            },
            "subject_alt_names": ["integration.test", "api.integration.test"]
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
                "serial_number": "ROOT_INT",
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
    
    # 2. Map and Save
    cert = map_cert_data_to_models(mock_data)
    db_session.add(cert)
    db_session.flush()
    
    # 3. Create Host and Scan
    host = Host(hostname="integration.test", port=443)
    db_session.add(host)
    db_session.flush()
    
    scan = CertificateScan(
        host_id=host.id,
        certificate_id=cert.id,
        raw_json=mock_data,
        scanned_at=datetime.now(timezone.utc)
    )
    db_session.add(scan)
    db_session.commit()
    
    # 4. Retrieval and Verification via Repository
    retrieved_cert = Repo.get_certificate_by_serial(db_session, "INTTEST123")
    assert retrieved_cert is not None
    assert retrieved_cert.subject_common_name == "integration.test"
    
    # Verify Relationships
    assert len(retrieved_cert.sans) == 2
    assert any(s.san_value == "api.integration.test" for s in retrieved_cert.sans)
    
    assert retrieved_cert.tls_detail.tls_version == "TLSv1.3"
    
    assert len(retrieved_cert.chain_entries) == 1
    assert retrieved_cert.chain_entries[0].serial_number == "ROOT_INT"
    
    assert retrieved_cert.security_check.strong_tls is True
    
    # Verify latest scan result logic
    latest_cert = Repo.get_latest_scan_result(db_session, host.id)
    assert latest_cert.id == retrieved_cert.id

def test_host_cache_logic(db_session):
    """Integration test: Verify host retrieval and scan status updates."""
    hostname = "cache.test"
    host = Host(hostname=hostname, port=443, last_scan_status="success", last_scan_at=datetime.now(timezone.utc))
    db_session.add(host)
    db_session.commit()
    
    retrieved_host = Repo.get_host(db_session, hostname)
    assert retrieved_host is not None
    assert retrieved_host.last_scan_status == "success"
    
def test_delete_host_cascades(db_session):
    """Integration test: Verify that deleting a host correctly handles its scan records."""
    # Setup
    host = Host(hostname="delete.test", port=443)
    cert = Certificate(serial_number="DEL123", not_before=datetime.now(), not_after=datetime.now())
    db_session.add(host)
    db_session.add(cert)
    db_session.flush()
    
    scan = CertificateScan(host_id=host.id, certificate_id=cert.id)
    db_session.add(scan)
    db_session.commit()
    
    # Delete Host
    db_session.delete(host)
    db_session.commit()
    
    # Verify Scan is gone
    scan_count = db_session.query(CertificateScan).filter_by(host_id=host.id).count()
    assert scan_count == 0
    
    # Certificate should still exist (it might be shared by other hosts)
    assert Repo.get_certificate_by_serial(db_session, "DEL123") is not None
