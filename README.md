# Enhanced Subdomain Checker 🔍

Advanced subdomain discovery and analysis tool with privacy features and comprehensive reporting capabilities.

*[Türkçe doküman için aşağıya bakınız](#türkçe-doküman)*

## Features

- **High Performance**: Asynchronous scanning with configurable concurrency
- **Multi-Protocol Support**: HTTP/HTTPS automatic detection
- **SSL Analysis**: Certificate validation and expiration checking
- **Technology Detection**: Web server and framework identification
- **Privacy Features**: Tor support, proxy rotation, anti-fingerprinting
- **Comprehensive Reporting**: CSV, JSON, Excel outputs with statistics
- **DNS Analysis**: A record resolution and validation
- **Cross-Platform**: Windows and Linux support

## Installation

### Requirements
- Python 3.10+ recommended
- Virtual environment (recommended)

### Setup
```bash
# Clone the repository
git clone https://github.com/yourusername/enhanced-subdomain-checker.git
cd enhanced-subdomain-checker

# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

# Install dependencies
pip install aiohttp xlsxwriter aiofiles tqdm requests dnspython

# Optional: For SOCKS proxy support
pip install aiohttp-socks
```

## Quick Start

### Basic Usage
```bash
# Simple scan
python pinger.py domains.txt

# High performance scan
python pinger.py domains.txt --concurrency 50 --timeout 5

# Verbose output
python pinger.py domains.txt --verbose
```

### Domain File Format
Create a text file with domains (one per line):
```
example.com
test.example.com
api.example.com
# Comments start with #
mail.example.com
```

## Advanced Usage

### Privacy & Anonymity
```bash
# Use Tor proxy
python pinger.py domains.txt --tor

# Custom proxy
python pinger.py domains.txt --proxy socks5://127.0.0.1:9050

# Full anonymity mode
python pinger.py domains.txt --tor --rotate-ua --anti-fingerprint --randomize

# Proxy rotation
python pinger.py domains.txt --proxy-list proxies.txt --rotate-proxy-per-req
```

### Performance Tuning
```bash
# Maximum performance
python pinger.py domains.txt --concurrency 100 --timeout 3 --delay 0.01

# Conservative scan
python pinger.py domains.txt --concurrency 10 --timeout 15 --delay 0.5

# Random delays for stealth
python pinger.py domains.txt --random-delay 0.1:2.0
```

### Custom Configuration
```bash
# Custom DNS servers
python pinger.py domains.txt --dns cloudflare
python pinger.py domains.txt --dns 8.8.8.8

# Custom headers
python pinger.py domains.txt --custom-headers '{"X-Custom":"value"}'

# Disable features
python pinger.py domains.txt --no-ssl --no-dns --no-tech
```

## Command Line Options

### Basic Options
- `--concurrency N`: Number of concurrent requests (default: 20)
- `--timeout N`: Request timeout in seconds (default: 8.0)
- `--delay N`: Delay between requests (default: 0.02)
- `--output-dir DIR`: Output directory (default: results)
- `--verbose`: Detailed output with progress

### Feature Controls
- `--no-dns`: Disable DNS checking
- `--no-ssl`: Disable SSL certificate checking
- `--no-tech`: Disable technology detection

### Privacy Options
- `--tor`: Use Tor proxy (127.0.0.1:9050)
- `--proxy URL`: Custom proxy (http://ip:port, socks5://ip:port)
- `--proxy-list FILE`: Proxy rotation from file
- `--proxy-auth USER:PASS`: Proxy authentication
- `--rotate-ua`: Rotate User-Agent strings
- `--anti-fingerprint`: Enable anti-fingerprinting measures
- `--randomize`: Randomize domain scan order
- `--fake-referer`: Use fake referer headers

### DNS Options
- `--dns PROVIDER`: Use specific DNS (cloudflare, google, quad9, opendns)
- `--custom-dns IP`: Custom DNS server IP

## Output Formats

The tool generates multiple output formats:

### CSV Report (`detailed_results.csv`)
Complete data with all fields for analysis

### JSON Report (`results.json`)
Machine-readable format for integration

### Excel Report (`advanced_results.xlsx`)
- Detailed results with formatting
- Statistics worksheet
- Charts and visual analysis

### Summary Report (`summary_report.md`)
- Scan statistics
- Top technologies found
- Fastest responding domains

## Sample Output

```
============================================================
SCAN COMPLETED IN 45.2 SECONDS
============================================================
Total Domains: 1,500
Active: 1,234 (82.3%)
Inactive: 266 (17.7%)
Rate: 33.2 domains/second
Avg Response Time: 145ms
HTTPS Support: 1,100 (73.3%)
Valid SSL: 1,050

Output Files:
  • CSV: results/detailed_results.csv
  • JSON: results/results.json
  • Excel: results/advanced_results.xlsx
  • Report: results/summary_report.md
```

## Privacy & Security

### Tor Integration
```bash
# Start Tor service first
# Then run with Tor
python pinger.py domains.txt --tor --verbose
```

### Proxy Configuration
```bash
# HTTP proxy
python pinger.py domains.txt --proxy http://proxy.example.com:8080

# SOCKS5 proxy with auth
python pinger.py domains.txt --proxy socks5://proxy.example.com:1080 --proxy-auth user:pass

# Proxy rotation
echo "socks5://proxy1.com:1080" > proxies.txt
echo "socks5://proxy2.com:1080" >> proxies.txt
python pinger.py domains.txt --proxy-list proxies.txt
```

## Troubleshooting

### Common Issues

#### Module Not Found Error
```bash
# Ensure virtual environment is activated
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate     # Windows

# Reinstall dependencies
pip install --upgrade -r requirements.txt
```

#### Permission Denied (Output Directory)
The tool will automatically use a temporary directory if it cannot create the output directory.

#### DNS Resolution Errors
```bash
# Use alternative DNS
python pinger.py domains.txt --dns google

# Disable DNS checking
python pinger.py domains.txt --no-dns
```

#### Proxy Connection Issues
```bash
# Test proxy connectivity first
curl --proxy socks5://127.0.0.1:9050 https://check.torproject.org/

# Use HTTP proxy instead of SOCKS
python pinger.py domains.txt --proxy http://proxy.example.com:8080
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Security Notice

This tool is intended for legitimate security testing and domain analysis. Users are responsible for ensuring they have proper authorization before scanning domains they do not own.

---

# Türkçe Doküman

## Gelişmiş Subdomain Tarayıcı 🔍

Gizlilik özellikleri ve kapsamlı raporlama yetenekleri ile gelişmiş subdomain keşif ve analiz aracı.

## Özellikler

- **Yüksek Performans**: Yapılandırılabilir eşzamanlılık ile asenkron tarama
- **Çoklu Protokol Desteği**: HTTP/HTTPS otomatik algılama
- **SSL Analizi**: Sertifika doğrulama ve son kullanma tarihi kontrolü
- **Teknoloji Tespiti**: Web sunucu ve framework tanımlama
- **Gizlilik Özellikleri**: Tor desteği, proxy rotasyonu, parmak izi önleme
- **Kapsamlı Raporlama**: İstatistikli CSV, JSON, Excel çıktıları
- **DNS Analizi**: A kaydı çözümleme ve doğrulama
- **Çapraz Platform**: Windows ve Linux desteği

## Kurulum

### Gereksinimler
- Python 3.10+ önerilir
- Sanal ortam (önerilir)

### Kurulum Adımları
```bash
# Repoyu klonla
git clone https://github.com/kullaniciadin/enhanced-subdomain-checker.git
cd enhanced-subdomain-checker

# Sanal ortam oluştur
python -m venv venv

# Sanal ortamı aktifleştir
# Windows:
venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

# Bağımlılıkları yükle
pip install aiohttp xlsxwriter aiofiles tqdm requests dnspython

# Opsiyonel: SOCKS proxy desteği için
pip install aiohttp-socks
```

## Hızlı Başlangıç

### Temel Kullanım
```bash
# Basit tarama
python pinger.py domains.txt

# Yüksek performanslı tarama
python pinger.py domains.txt --concurrency 50 --timeout 5

# Ayrıntılı çıktı
python pinger.py domains.txt --verbose
```

### Domain Dosya Formatı
Her satırda bir domain olacak şekilde metin dosyası oluşturun:
```
example.com
test.example.com
api.example.com
# Yorumlar # ile başlar
mail.example.com
```

## Gelişmiş Kullanım

### Gizlilik ve Anonimlik
```bash
# Tor proxy kullan
python pinger.py domains.txt --tor

# Özel proxy
python pinger.py domains.txt --proxy socks5://127.0.0.1:9050

# Tam anonimlik modu
python pinger.py domains.txt --tor --rotate-ua --anti-fingerprint --randomize

# Proxy rotasyonu
python pinger.py domains.txt --proxy-list proxies.txt --rotate-proxy-per-req
```

### Performans Ayarlama
```bash
# Maksimum performans
python pinger.py domains.txt --concurrency 100 --timeout 3 --delay 0.01

# Konservatif tarama
python pinger.py domains.txt --concurrency 10 --timeout 15 --delay 0.5

# Gizlilik için rastgele gecikmeler
python pinger.py domains.txt --random-delay 0.1:2.0
```

## Komut Satırı Seçenekleri

### Temel Seçenekler
- `--concurrency N`: Eşzamanlı istek sayısı (varsayılan: 20)
- `--timeout N`: İstek zaman aşımı saniye (varsayılan: 8.0)
- `--delay N`: İstekler arası gecikme (varsayılan: 0.02)
- `--output-dir DIR`: Çıktı dizini (varsayılan: results)
- `--verbose`: İlerlemeli ayrıntılı çıktı

### Özellik Kontrolleri
- `--no-dns`: DNS kontrolünü devre dışı bırak
- `--no-ssl`: SSL sertifika kontrolünü devre dışı bırak
- `--no-tech`: Teknoloji tespitini devre dışı bırak

### Gizlilik Seçenekleri
- `--tor`: Tor proxy kullan (127.0.0.1:9050)
- `--proxy URL`: Özel proxy (http://ip:port, socks5://ip:port)
- `--proxy-list FILE`: Dosyadan proxy rotasyonu
- `--proxy-auth USER:PASS`: Proxy kimlik doğrulama
- `--rotate-ua`: User-Agent rotasyonu
- `--anti-fingerprint`: Parmak izi önleme önlemlerini etkinleştir
- `--randomize`: Domain tarama sırasını rastgeleleştir

## Çıktı Formatları

Araç birden fazla çıktı formatı üretir:

### CSV Raporu (`detailed_results.csv`)
Analiz için tüm alanları içeren tam veri

### JSON Raporu (`results.json`)
Entegrasyon için makine okunabilir format

### Excel Raporu (`advanced_results.xlsx`)
- Formatlı ayrıntılı sonuçlar
- İstatistik çalışma sayfası
- Grafik ve görsel analiz

### Özet Raporu (`summary_report.md`)
- Tarama istatistikleri
- Bulunan en yaygın teknolojiler
- En hızlı yanıt veren domainler

## Örnek Çıktı

```
============================================================
TARAMA 45.2 SANİYEDE TAMAMLANDI
============================================================
Toplam Domain: 1,500
Aktif: 1,234 (%82.3)
İnaktif: 266 (%17.7)
Hız: 33.2 domain/saniye
Ort. Yanıt Süresi: 145ms
HTTPS Desteği: 1,100 (%73.3)
Geçerli SSL: 1,050

Çıktı Dosyaları:
  • CSV: results/detailed_results.csv
  • JSON: results/results.json
  • Excel: results/advanced_results.xlsx
  • Rapor: results/summary_report.md
```

## Sorun Giderme

### Yaygın Sorunlar

#### Modül Bulunamadı Hatası
```bash
# Sanal ortamın aktif olduğundan emin olun
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate     # Windows

# Bağımlılıkları yeniden yükle
pip install --upgrade -r requirements.txt
```

#### İzin Reddedildi (Çıktı Dizini)
Araç, çıktı dizinini oluşturamıyorsa otomatik olarak geçici dizin kullanır.

#### DNS Çözümleme Hataları
```bash
# Alternatif DNS kullan
python pinger.py domains.txt --dns google

# DNS kontrolünü devre dışı bırak
python pinger.py domains.txt --no-dns
```

## Güvenlik Uyarısı

Bu araç meşru güvenlik testleri ve domain analizi için tasarlanmıştır. Kullanıcılar, sahip olmadıkları domainleri taramadan önce uygun yetkilendirmeye sahip olduklarından emin olmakla yükümlüdür.

## Lisans

Bu proje MIT Lisansı altında lisanslanmıştır - ayrıntılar için [LICENSE](LICENSE) dosyasına bakın.