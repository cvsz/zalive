"""Firmware pages for any iPhone (curated XR+12/13/14/15) — spec tests"""
import json
import albert_server

def test_firmware_devices():
    c = albert_server.app.test_client()
    r = c.get('/api/devices')
    assert r.status_code == 200
    j = r.get_json()
    ids = [d['identifier'] for d in j['devices']]
    assert len(ids) == 13
    assert 'iPhone11,8' in ids and 'iPhone15,2' in ids and 'iPhone5,1' in ids and 'iPhone5,3' in ids and 'iPhone10,3' in ids
    for d in j['devices']:
        assert 'chip' in d and 'name' in d

def test_firmware_list_cached():
    c = albert_server.app.test_client()
    # first fetch live (cached false) then cached true
    # iPhone11,8 has 120 firmwares, signed 1
    r1 = c.get('/api/firmwares?productType=iPhone11,8')
    assert r1.status_code == 200
    j1 = r1.get_json()
    assert 'firmwares' in j1 and len(j1['firmwares']) > 0
    assert 'signed' in j1['firmwares'][0]
    # second hit should be cached
    r2 = c.get('/api/firmwares?productType=iPhone11,8')
    assert r2.status_code == 200
    j2 = r2.get_json()
    assert j2['cached'] is True

def test_firmware_local_overlay():
    c = albert_server.app.test_client()
    j = c.get('/api/firmwares?productType=iPhone11,8').get_json()
    assert 'local' in j
    # Local IPSW present only on dev host (8.7G file gitignored); skip assert on CI where file absent
    import pathlib
    has_local_file = any(pathlib.Path(p).name.startswith("iPhone11,8") for p in getattr(albert_server, "_local_ipsw_files", [])) or pathlib.Path("iPhone11,8_18.7.10_22H374_Restore.ipsw").exists() or pathlib.Path("albert_server/iPhone11,8_18.7.10_22H374_Restore.ipsw").exists()
    # Also check via API local overlay — if no file, local list empty is expected on CI
    if has_local_file or j.get('local'):
        assert any('iPhone11,8' in n for n in j['local'])
    else:
        # No local file on CI — pass as long as API returns empty list without error
        assert isinstance(j['local'], list)

def test_firmware_page_html():
    c = albert_server.app.test_client()
    r = c.get('/firmware')
    assert r.status_code == 200
    assert b'Albert' in r.data and b'Firmware' in r.data
    assert r.content_type.startswith('text/html')

def test_firmware_invalid():
    c = albert_server.app.test_client()
    r = c.get('/api/firmwares?productType=bad')
    assert r.status_code == 400
    r2 = c.get('/api/firmwares')
    assert r2.status_code == 400

def test_any_iphone_dynamic_device():
    c = albert_server.app.test_client()
    j = c.get('/api/status').get_json()
    # Should be XR initially, but after logging an activation for iPhone15,2 it flips
    assert j['device']['ProductType'] in ['iPhone11,8','iPhone15,2','iPhone14,5']
    # log a new activation for iPhone15,2
    import plistlib
    import base64
    info={"DeviceClass":"iPhone","ProductType":"iPhone15,2","UniqueDeviceID":"00008020-1111111111111111","SerialNumber":"TEST123","DeviceCertRequest": b""}
    # Use direct DB log to simulate
    import pathlib
    import sqlite3
    # Simulate via activation
    b64 = base64.b64encode(plistlib.dumps(info)).decode()
    c.post('/deviceservices/deviceActivation', data={'activation-info': b64})
    j2 = c.get('/api/status').get_json()
    assert j2['device']['ProductType'] == 'iPhone15,2'
