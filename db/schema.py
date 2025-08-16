# db/schema.py

from db.models import MODEL_REGISTRY


def setup_database(cursor):
    for model in MODEL_REGISTRY.values():
        model.create_table(cursor)


def insert_initial_data(cursor):
    from db.models import Host, Url, Software, VersionSoft, CVE, ScanResult

    Host.insert(cursor, hostname="example.com", ip_address="93.184.216.34")
    Url.insert(cursor, host_id=1, url="https://example.com")
    Software.insert(cursor, host_id=1, name="Nginx")
    VersionSoft.insert(cursor, software_id=1, version="1.18.0", is_latest=False)
    VersionSoft.insert(cursor, software_id=1, version="1.24.0", is_latest=True)
    CVE.insert(cursor, cve_id="CVE-2024-5678", description="SQL Injection", severity="High")
    ScanResult.insert(cursor, url_id=1, cve_id=1, status="Exploitable")
