#!/bin/zsh
###############################################################################
# SentinelScan - Hızlı Test Scripti
# Temel testleri hızlıca çalıştırır
###############################################################################

# Renkler
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

echo "${BLUE}🚀 SentinelScan - Hızlı Test${NC}"
echo "================================"

# Dizin değiştir
cd "$(dirname "$0")"

# Virtual environment aktif et
if [ -d ".venv" ]; then
    source .venv/bin/activate
    echo "${GREEN}✓${NC} Venv aktif"
else
    echo "${YELLOW}⚠${NC} Venv yok, oluşturuluyor..."
    python3 -m venv .venv
    source .venv/bin/activate
    pip install -q -r requirements.txt
fi

echo ""
echo "${BLUE}Test 1: Yardım${NC}"
python main.py --help | head -15

echo ""
echo "${BLUE}Test 2: Header Check (example.com)${NC}"
python main.py headers --url https://example.com 2>&1 | tail -15

echo ""
echo "${BLUE}Test 3: Header Check (test.io)${NC}"
python main.py headers --url https://test.io 2>&1 | tail -15

echo ""
echo "${BLUE}Test 4: Port Scan (test.io)${NC}"
python main.py portscan --target test.io --ports 80,443 2>&1 | tail -10

echo ""
echo "${BLUE}Test 5: XSS Scanner${NC}"
python main.py xss --url "https://httpbin.org/get" 2>&1 | tail -10

echo ""
echo "${BLUE}Test 6: Modül Kontrolü${NC}"
for mod in header_checker port_scanner xss_scanner sql_injection_scanner subdomain_finder; do
    if [ -f "modules/${mod}.py" ]; then
        echo "${GREEN}✓${NC} ${mod}.py"
    else
        echo "${RED}✗${NC} ${mod}.py"
    fi
done

echo ""
echo "${BLUE}Test 7: Log Kontrolü${NC}"
if [ -d "logs" ]; then
    LOG_COUNT=$(ls -1 logs/*.log 2>/dev/null | wc -l | tr -d ' ')
    echo "${GREEN}✓${NC} logs/ dizini var ($LOG_COUNT dosya)"
    if [ $LOG_COUNT -gt 0 ]; then
        echo "Son log:"
        ls -t logs/*.log 2>/dev/null | head -1
    fi
else
    echo "${YELLOW}⚠${NC} logs/ dizini yok"
fi

echo ""
echo "${GREEN}✅ Hızlı test tamamlandı!${NC}"
echo ""
echo "Detaylı testler için: python main.py [command] --help"
echo "Kullanılabilir komutlar: headers, portscan, xss, sqli, subdomain"
echo ""

