# scanner/wappalyzer.py

import subprocess
import json
from db.models import Software, VersionSoft


def run_wappalyzer(target):
    print(f"[Wappalyzer] Сканируем {target}...")
    try:
        result = subprocess.run(["wappalyzer", target, "-f", "json"], capture_output=True, text=True, check=True)
        return json.loads(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"Ошибка при запуске Wappalyzer: {e}")
        return {}


def process_wappalyzer_result(data, cursor, host_id):
    technologies = data.get("technologies", [])
    for tech in technologies:
        name = tech.get("name")
        versions = tech.get("versions", [])

        Software.insert(cursor, host_id=host_id, name=name)
        software_id = cursor.lastrowid

        for version in versions:
            VersionSoft.insert(cursor, software_id=software_id, version=version, is_latest=False)
