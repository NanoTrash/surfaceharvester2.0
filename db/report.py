# db/report.py

def find_vulnerable_versions(cursor, hostname):
    sql = """
        SELECT h.hostname, s.name, v.version, sr.status, c.cve_id
        FROM host h
        JOIN software s ON s.host_id = h.id
        JOIN versionsoft v ON v.software_id = s.id
        JOIN scanresult sr ON sr.url_id IN (
            SELECT u.id FROM url u WHERE u.host_id = h.id
        )
        JOIN cve c ON c.id = sr.cve_id
        WHERE h.hostname = ? AND sr.status = 'Exploitable'
    """
    cursor.execute(sql, (hostname,))
    return cursor.fetchall()

def find_outdated_software(cursor, hostname):
    sql = """
        SELECT h.hostname, s.name, v.version
        FROM host h
        JOIN software s ON s.host_id = h.id
        JOIN versionsoft v ON v.software_id = s.id
        WHERE h.hostname = ? AND v.is_latest = 0
    """
    cursor.execute(sql, (hostname,))
    return cursor.fetchall()

def find_software_with_cve(cursor):
    sql = """
        SELECT s.name, v.version, c.cve_id, c.description
        FROM software s
        JOIN versionsoft v ON v.software_id = s.id
        JOIN scanresult sr ON sr.url_id IN (
            SELECT u.id FROM url WHERE u.host_id = s.host_id
        )
        JOIN cve c ON c.id = sr.cve_id
    """
    cursor.execute(sql)
    return cursor.fetchall()

def show_report(cursor, hostname):
    print("\n[1] Уязвимые версии ПО на хосте:")
    for row in find_vulnerable_versions(cursor, hostname):
        print(row)

    print("\n[2] Устаревшее ПО на хосте:")
    for row in find_outdated_software(cursor, hostname):
        print(row)

    print("\n[3] ПО и версии с CVE:")
    for row in find_software_with_cve(cursor):
        print(row)
