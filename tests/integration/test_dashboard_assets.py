from pathlib import Path

def test_dashboard_static_files_exist():
    base = Path('src/dashboard/static')
    assert (base / 'js' / 'main.js').exists()
