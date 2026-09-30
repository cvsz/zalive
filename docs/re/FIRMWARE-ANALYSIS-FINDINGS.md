# ผลการวิเคราะห์ firmware เพิ่มเติม (iOS 18.7.10 / 22H374)

บันทึกผล RE สองเรื่องที่เคยค้างเป็นคำถามเปิด ได้แก่ iBoot ที่คาดว่ามี
ชั้น LZFSE ที่สอง และ AEA container ของ sealed system

ทั้งสองเรื่องนี้วิเคราะห์ด้วยข้อมูลจริงจาก `firmware/` (gitignored) ไม่ใช่จากเอกสาร
ของบุคคลที่สาม ดังนั้นข้อสรุปที่ต่างจากความเชื่อเดิมมีเหตุผลรองรับ

## iBoot: ไม่มีชั้นที่สอง — เป็นโค้ด ARM64 ดิบ

### ความเชื่อเดิมที่ผิด

เคยบันทึกว่า `iBoot.n841.RELEASE.im4p` หลังถอด LZFSE แล้วจะได้ Mach-O ที่ถูก
บีบอัดอีกชั้น โดยอ้างว่าเจอ magic `0x90000000`

### สิ่งที่พบจริง

```
firmware/Firmware/all_flash/iBoot.n841.RELEASE.im4p   1,507,241 bytes

SEQUENCE
  APP  "IM4P"
  APP  "ibot"
  APP  "iBoot-11881.1..."
  OCTET STRING @43  len=1,507,183  → payload เริ่มด้วย "bvx2" (LZFSE)
  SEQUENCE (ท้ายไฟล์)
```

หลัง `lzfse.decompress()` ได้ **2,159,736 bytes** และหัวไฟล์เป็น:

```
+0   00 00 00 90  00 00 00 91  c1 17 00 58  03 da 00 94
+16  3f 00 00 eb  00 0a 00 54  82 17 00 58  42 00 01 cb
```

### `0x90000000` คือคำสั่ง ARM64 ไม่ใช่ header

`00 00 00 90` อ่านเป็น little-endian uint32 ได้ `0x90000000` ซึ่งดูเหมือน magic
แต่จริง ๆ เป็น opcode ของคำสั่ง ARM64 ยืนยันด้วย capstone 5.0.7:

```
0x0000:  adrp    x0, #0
0x0004:  add     x0, x0, #0
0x0008:  ldr     x1, #0x300
0x000c:  bl      #0x36818
0x0010:  cmp     x1, x0
0x0014:  b.eq    #0x154
0x0018:  ldr     x2, #0x308
0x001c:  sub     x2, x2, x1
0x0020:  add     x2, x2, #0x3f
0x0024:  and     x2, x2, #0xffffffffffffffc0
```

ลำดับนี้คือ entry stub มาตรฐานของ iBoot (หาฐานแอดเดรส → โหลดค่า → เรียกฟังก์ชัน
→ เทียบค่า → สาข) ไม่มี Mach-O container ห่ออยู่ และไม่มีการบีบอัดชั้นที่สอง

### ข้อสรุป

- LZFSE มี**ชั้นเดียว** คือ OCTET STRING ของ IMG4
- ผลลัพธ์เป็น **raw ARM64 code** ไม่ใช่ Mach-O
- การหา Mach-O magic (`cffaedfe`, `cefaedfe`, `cafebabe`) ทั้งไฟล์ไม่พบเลย
- ไฟล์ที่ถอดแล้วมี `bvx2` อีกชุดที่ offset 1,091,440 และ `IM4P` ที่ 1,033,149
  แปลว่า iBoot ฝัง payload อื่นไว้ข้างใน (ต้องวิเคราะห์ต่อถ้าสนใจ)

### หมายเหตุเรื่อง IMG4 parser

`scripts/parse_trustcache.py` หา OCTET STRING ที่ "กินพอดีท้ายไฟล์" ซึ่งใช้ได้กับ
trustcache แต่ใช้กับ iBoot ไม่ได้ เพราะ iBoot มี SEQUENCE ต่อท้าย OCTET STRING
ถ้าจะใช้ทั่วไปต้องเดิน TLV ให้ครบแทน

## AEA: เข้ารหัสทั้งไฟล์ — ถอดไม่ได้โดยไม่มี key จาก Apple

### โครงสร้าง header

```
+00  41 45 41 31              "AEA1"
+04  01 00 00 00              version = 1
+08  48 08 00 00              = 2120
+0C  30 00 00 00              = 48
+10  "com.apple.wkms.url\0"   ป้ายของ key
     "https://wkms.sd.apple.com"
     45 03 00 00              = 837  (ความยาว auth-data)
     "com.apple.wkms.auth-data\0"
     "CVsCQYot9a1/CYcnWqq336h8ZF+uA/..."   (base64)
```

ไฟล์ `094-31934-038.dmg.aea` = 6,576,668,672 bytes (6.5 GB)
ไฟล์ `094-32062-038.dmg.aea` = 1,677,721,600 bytes

### เนื้อหาเข้ารหัสทั้งก้อน

วัด entropy ทีละ 1 MiB ตั้งแต่ต้นจนถึง 64 MiB ได้ **8.00 bits/byte** ทุกบล็อก
แปลว่าไม่มี plaintext เหลือให้วิเคราะห์ นอกจาก header ไม่กี่ร้อยไบต์

### ทำไมถอดไม่ได้

- `com.apple.wkms.url` ชี้ไปที่ **WKMS** (Wireless Key Management Service) ของ Apple
- key ถูกส่งมาหลังอุปกรณ์พิสูจน์ตัวตนกับ SEP/SE ของมันเอง
- ไม่มี key ใน IPSW และไม่มีทางคำนวณได้จากเครื่องโดยไม่มีอุปกรณ์
- นี่เป็นกลไกป้องกันลิขสิทธิ์ของ Apple โดยเจตนา ไม่ใช่สิ่งที่แหวกเลี่ยงได้

### ข้อสรุป

- ระบุรูปแบบ container ได้แล้ว (`AEA1`, version 1, key label + WKMS URL + base64 auth-data)
- **ถอดเนื้อหาไม่ได้** และไม่ควรพยายามฝืน เพราะต้องพึ่ง key ที่ Apple คุม
- ผลกระทบต่อโปรเจกต์: restore ทำงานได้เพราะอุปกรณ์ถอด AEA เองผ่าน
  activation process ของ Apple ส่วน `firmware_server.py` เกี่ยวข้องกับ IPSW
  components ที่ไม่ได้เข้ารหัส (เช่น kernelcache) เท่านั้น

## เครื่องมือที่ใช้

- `lzfse` (Python binding) — ถอด LZFSE
- `capstone` 5.0.7 — ถอด ARM64
- `scripts/parse_trustcache.py` — เดิน TLV ของ IMG4

ทั้งหมดมีอยู่ใน `venv/` แล้ว ไม่ต้องติดตั้งเพิ่ม
