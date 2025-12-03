# SentinelScan - Kullanım Kılavuzu

## Hızlı Başlangıç

```bash
python main.py <komut> [parametreler]
```

## Komutlar

### 1. HTTP Header Kontrolü
```bash
python main.py headers --url https://example.com
```

### 2. Port Tarama
```bash
# Varsayılan (1-1000)
python main.py portscan --target example.com

# Özel portlar
python main.py portscan --target 192.168.1.1 --ports 80,443,8080
```

### 3. XSS Tarama
```bash
python main.py xss --url https://test-site.com
```

### 4. SQL Injection Tarama
```bash
python main.py sqli --url https://test-site.com/login
```

### 5. Subdomain Bulma
```bash
# Basit tarama
python main.py subdomain --domain example.com

# Özel wordlist ve çıktı
python main.py subdomain --domain example.com \
  --wordlist wordlist.txt \
  --threads 20 \
  --output results.txt
```

## Parametreler

| Parametre | Açıklama | Varsayılan |
|-----------|----------|------------|
| `--url` | Hedef URL | - |
| `--target` | Hedef IP/domain | - |
| `--domain` | Hedef domain | - |
| `--ports` | Port aralığı | 1-1000 |
| `--wordlist` | Subdomain listesi | Built-in |
| `--threads` | Thread sayısı | 10 |
| `--output` | Çıktı dosyası | - |

## Loglar

Tüm taramalar otomatik olarak kaydedilir:
```
logs/sentinelscan_YYYYMMDD_HHMMSS.log
```

## Hızlı Test

```bash
./quick_test.sh
```

