# คู่มืออุปกรณ์และการใช้งานเชิงลึก

เอกสารนี้กู้เนื้อหาที่หายไปจาก `README.md` ตอนปรับเอกสารเป็นรุ่นกระชับ และ
เพิ่มเฉพาะข้อเท็จจริงที่ยืนยันกับโค้ดปัจจุบันแล้ว

> **ทำไมแยกเป็นไฟล์นี้** — README ควรอ่านจบใน 5 นาที รายละเอียดเชิงลึก
> ยาว 8 กิโลไบต์ทำให้ README กลายเป็นคู่มือที่ไม่มีใครเปิดอ่าน

## อุปกรณ์ที่รองรับ

โปรเจกต์รองรับ iPhone 5 → 15 Pro (A6–A16) รวม 13 โมเดลที่คัดมาไว้ อ่านค่า
`ProductType` แบบไดนามิก จึงไม่ต้องแก้โค้ดเมื่อเพิ่มรุ่น

รายการเต็มและเวอร์ชัน iOS ที่เคยทดสอบ: ดู [IPSW_REVERSE_ENGINEERING.md](IPSW_REVERSE_ENGINEERING.md)

อุปกรณ์ที่ใช้ทดสอบจริงล่าสุดคือ iPhone XR (`iPhone11,8`) บน iOS 18.7.10 (`22H374`)

## ขั้นตอนการ restore และ activate

### เข้า Recovery Mode

```bash
ideviceenterrecovery <UDID>
```

### restore ผ่าน proxy

```bash
export HTTPS_PROXY=http://127.0.0.1:18090
export HTTP_PROXY=http://127.0.0.1:18090
idevicerestore -e latest.ipsw
```

### หลัง restore อุปกรณ์จะพยายาม activate เอง

- ทราฟฟิกวิ่งผ่าน mitmproxy
- **เฉพาะ `albert.apple.com` ถูก redirect ไปที่ Albert local** ส่วน
  `gs.apple.com` (TSS) ปล่อยผ่านไปที่ Apple ตามปกติ
- Albert local ตอบ activation record ที่ถูกต้อง
- TSS signing ทำโดย `firmware-server` ซึ่งออก APTicket ด้วย FairPlay key

> ดู [../docs/RUNBOOK.md](RUNBOOK.md) สำหรับขั้นตอนระดับ production

## activate ด้วยตนเองหลัง restore

ถ้าอุปกรณ์บูตถึงหน้า Hello แต่ activate ไม่ขึ้น:

```bash
# pair อุปกรณ์ก่อน
idevicepair pair

# ดูสถานะ activation
ideviceactivation state

# activate ผ่าน local server
python activate_device.py --udid <UDID> --albert-url http://127.0.0.1:18090
```

### ทางเลือก: ใช้ pymobiledevice3 ตรง ๆ

```bash
pymobiledevice3 mobileactivation activate --skip-apple-id-query
```

## ตัวเลือกของ activate_device.py

`activate_device.py` เป็น **client** — flag ทุกตัวในตารางนี้มาจาก `parse_args` ที่ `activate_device.py:711-721`
(flag ฝั่ง server อยู่คนละชุด ดูหัวข้อถัดไป)

| flag | ความหมาย |
|---|---|
| `--udid UDID` | ระบุอุปกรณ์ (ถ้าไม่ระบุจะตรวจอัตโนมัติ) |
| `--albert-url URL` | URL ของ Albert local เช่น `http://127.0.0.1:18090` |
| `--info` | พิมพ์สถานะเครื่องแล้วออก ไม่ activate |
| `--json` | ผลลัพธ์เป็น JSON |
| `--method METHOD` | เลือกวิธี activation |
| `--retries N` | จำนวนครั้งที่ลองใหม่ |
| `--timeout SEC` | timeout ต่อคำขอ |
| `--skip-apple-id` | ข้ามการถาม Apple ID |

## ตัวเลือกของ albert_server.py

`albert_server.py` **มี** flag ฝั่ง server จริง (ยืนยันที่ `albert_server.py:3707-3710`):

| flag | ค่าเริ่มต้น | ความหมาย |
|---|---|---|
| `--host HOST` | `0.0.0.0` | bind address — ค่านี้ผูกกับ LAN exposure ดูหัวข้อความปลอดภัย |
| `--port PORT` | `8080` | **ไม่ใช่ 18090** — production ใช้ gunicorn ตาม `gunicorn_conf.py` ซึ่ง default `18090` |
| `--ssl-cert FILE` | — | certificate สำหรับ HTTPS |
| `--ssl-key FILE` | — | private key สำหรับ HTTPS |
| `--no-debug` | — | ปิด debug mode |
| `--allow-no-risk` | — | ยอมให้ start โดยไม่มี `ALBERT_ACCEPT_RISK=1` (มี log เตือน) |
| `--rotate-fairplay` | — | ลบและสร้าง `certs/fairplay.key`/`.crt` ใหม่ |

> **หมายเหตุการแก้ไข:** เอกสารรุ่นก่อนหน้าของโปรเจกต์ระบุว่า flag `--host` /
> `--port` / `--ssl-cert` / `--ssl-key` "ไม่เคยมีในโค้ด" ซึ่ง**ผิด** — flag เหล่านี้มีจริง
> แต่การค้นหาเดิมใช้ regex ที่จับเฉพาะ double-quote จึงพลาด single-quote
> ที่ `add_argument` ใช้ ส่วนที่ README รุ่นเดิมระบุผิดจริงคือค่า default ของ `--port`
> (เขียน `18090` แต่จริงคือ `8080`)

## ตัวแปรสภาพแวดล้อม

อ่านค่าจาก `.env` (ดู `.env.example` สำหรับรายการเต็ม)

| ตัวแปร | ค่าเริ่มต้น | หมายเหตุ |
|---|---|---|
| `ALBERT_BIND_ADDRESS` | `127.0.0.1` | ฝั่ง host ของ Docker port publish — **อย่า**ใช้กับ process ใน container |
| `ALBERT_HTTP_PORT` | `18090` | พอร์ต HTTP |
| `ALBERT_HTTPS_PORT` | `18443` | พอร์ต HTTPS |
| `ALBERT_HOST` | `0.0.0.0` | bind ของ gunicorn ตาม `gunicorn_conf.py` |
| `ALBERT_MODE` | `prod` | โหมดการทำงาน |
| `ALBERT_ADMIN_TOKEN` | — | **บังคับ** ถ้าไม่ตั้ง endpoint `/api/*` จะปฏิเสธทุกคำขอ |
| `ALBERT_ACCEPT_RISK` | `0` | ต้องตั้งเป็น `1` โดย operator อย่างชัดเจนถึงจะทำงาน |
| `MITMPROXY_WEB_PASSWORD` | — | **บังคับ** compose จะไม่ start ถ้าไม่ตั้ง |
| `FAIRPLAY_KEY_PATH` | `certs/fairplay.key` | ตำแหน่ง private key |
| `FAIRPLAY_CERT_PATH` | `certs/fairplay.crt` | ตำแหน่ง certificate chain |
| `LOCAL_ALBERT_HOST` / `_PORT` / `_SCHEME` | `127.0.0.1` / `18090` / `http` | ปลายทางที่ proxy redirect ไปหา |

### สร้าง certificate สำหรับ dev

```bash
openssl req -x509 -newkey rsa:2048 -nodes -keyout server.key -out server.crt \
    -days 365 -subj "/CN=albert.local"
chmod 600 server.key
```

production ใช้ gunicorn บน `18090` หลัง TLS ของ mitmproxy — ดู
[../SECURITY.md](../SECURITY.md)

## TLS ผ่าน mitmproxy

- CA ของ mitmproxy อยู่ที่ `~/.mitmproxy`
- ติดตั้ง CA บนอุปกรณ์ผ่าน `http://mitm.it` หลังตั้ง Wi-Fi proxy เป็น host:18090
- mTLS ระหว่าง proxy → Albert ดูคู่มือที่ [RUNBOOK.md](RUNBOOK.md#mtls-proxy--albert)

## Proxy configuration

`firmware_restore_proxy.py` อ่านค่าจาก environment:

| ตัวแปร | ค่าเริ่มต้น | หมายเหตุ |
|---|---|---|
| `LOCAL_ALBERT_HOST` | `127.0.0.1` | ใน Docker ค่านี้คือ `albert-server` |
| `LOCAL_ALBERT_PORT` | `18090` | |
| `LOCAL_ALBERT_SCHEME` | `http` | `http` (อยู่หลัง TLS ของ mitmproxy) หรือ `https` |
| `ALBERT_HOSTS` | `albert.apple.com` | เฉพาะ host นี้ที่ถูก intercept — `gs.apple.com` ปล่อยผ่าน |

## การแก้ปัญหา

### อุปกรณ์ไม่ถูกตรวจจับ

1. ตรวจการเชื่อมต่อ USB
2. `ideviceinfo` เพื่อยืนยันว่า libimobiledevice เห็นเครื่อง
3. restart `usbmuxd` แล้วลองใหม่

### activate ไม่สำเร็จ

1. ดูสถานะด้วย `ideviceactivation state`
2. ตรวจ log ของ mitmproxy ว่ามี request ไปยัง `albert.apple.com` หรือไม่
3. ยืนยันว่า `ALBERT_ADMIN_TOKEN` ตรงกับที่ใส่ใน header

### Certificate pinning

อุปกรณ์ที่ pin certificate จะไม่ยอมรับ CA ของ mitmproxy ต้องใช้
[activate_device.py](../activate_device.py) ผ่าน USB แทน ซึ่งไม่ต้องผ่าน
TLS layer

### proxy ไม่ intercept

- ยืนยันว่า mitmproxy กำลังรันที่พอร์ต production
- ตรวจว่า device ตั้ง Wi-Fi proxy ชี้ไปที่ host ที่ถูกต้อง
- `ALBERT_HOSTS` ต้องมี `albert.apple.com` ไม่ใช่ wildcard

## ข้อจำกัดที่ทราบแล้ว

- local Albert สร้าง FairPlay handshake ไม่ได้ ต้องพึ่ง handshake ที่ Apple
  เซิร์ฟเวอร์ส่งมา
- Apple อาจปฏิเสธเมื่อบัญชี Apple ID ถูก disable — เป็นข้อจำกัดฝั่ง Apple
  ไม่ใช่บั๊กของ local server
- activation จริงจึงทำได้เมื่อบัญชีอยู่ในสถานะใช้งาน

## ดูเพิ่มเติม

- [RUNBOOK.md](RUNBOOK.md) — ขั้นตอนระดับ production
- [architecture.md](architecture.md) — โครงสร้างระบบ
- [../SECURITY.md](../SECURITY.md) — นโยบายความปลอดภัย
- [IMEI_ACTIVATION_REVERSE_ENGINEERING.md](IMEI_ACTIVATION_REVERSE_ENGINEERING.md) — ผลการวิเคราะห์ protocol
