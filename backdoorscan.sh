#!/bin/bash

################################################ IGNORE ################################################

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

CRITICAL_COUNT=0
HIGH_COUNT=0
MEDIUM_COUNT=0
FOUND_ITEMS=()

################################################ IGNORE ################################################

############################################# CONFIGURATION ############################################

SCAN_PATH="/path/to/scan/"  # Change this to the directory you want to scan (e.g., /var/lib/pterodactyl/volumes/298cd9c2-8f38-15a1-99a3-d92eadd1xer5/txData/ESXLegacy_6R7D90.base/resources/)

REPORT_FILE="lunashield_report_$(date +%m%d_%H%M%S).txt"

############################################# CONFIGURATION ############################################

clear
echo -e "${CYAN}"
echo "╔═══════════════════════════════════════════════════════════════════╗"
echo "║                    ╦  ╦ ╦╔╗╔╔═╗╔═╗╦ ╦╦╔═╗╦  ╔╦╗                   ║"
echo "║                    ║  ║ ║║║║╠═╣╚═╗╠═╣║║╣ ║   ║║                   ║"
echo "║                    ╩═╝╚═╝╝╚╝╩ ╩╚═╝╩ ╩╩╚═╝╩═╝═╩╝                   ║"
echo "║                                                                   ║"
echo "║                 Advanced Malware Detection System                 ║"
echo "║                            by Soul <3                             ║"
echo "╚═══════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo ""

echo "╦  ╦ ╦╔╗╔╔═╗╔═╗╦ ╦╦╔═╗╦  ╔╦╗" > "$REPORT_FILE"
echo "║  ║ ║║║║╠═╣╚═╗╠═╣║║╣ ║   ║║" >> "$REPORT_FILE"
echo "╩═╝╚═╝╝╚╝╩ ╩╚═╝╩ ╩╩╚═╝╩═╝═╩╝" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"
echo "Path: $SCAN_PATH" >> "$REPORT_FILE"
echo ""

show_loading() {
    echo -e "${CYAN}Configuration:${NC}"
    echo -e "${BLUE}Path: ${YELLOW}$SCAN_PATH${NC}"
    echo ""
    
    echo -e "${CYAN}Initializing scan${NC}"
    sleep 1.5
    echo -e "${GREEN}✅ Done${NC}"
    echo ""
    
    echo -e "${CYAN}Checking for Miaus malware patterns${NC}"
    sleep 1.7
    echo -e "${GREEN}✅ Done${NC}"
    echo ""
    
    echo -e "${CYAN}Checking for Cipher/Blum backdoor patterns${NC}"
    sleep 1.6
    echo -e "${GREEN}✅ Done${NC}"
    echo ""
    
    echo -e "${CYAN}Analyzing suspicious code patterns${NC}"
    sleep 1.8
    echo -e "${GREEN}✅ Done${NC}"
    echo ""
    
    echo -e "${CYAN}Scanning for hidden files${NC}"
    sleep 1.4
    echo -e "${GREEN}✅ Done${NC}"
    echo ""
    
    echo -e "${CYAN}Generating report${NC}"
    echo ""
    
    sleep 0.5
}

scan() {
    local pattern="$1"
    local desc="$2"
    local severity="$3"
    local ext="$4"
    
    if [ "$ext" == "js" ]; then
        results=$(grep -rln "$pattern" "$SCAN_PATH" --include="*.js" 2>/dev/null | grep -v node_modules | grep -v '.min.js')
    elif [ "$ext" == "lua" ]; then
        results=$(grep -rln "$pattern" "$SCAN_PATH" --include="*.lua" 2>/dev/null | grep -v node_modules)
    else
        results=$(grep -rln "$pattern" "$SCAN_PATH" --include="*.lua" --include="*.js" 2>/dev/null | grep -v node_modules | grep -v '.min.js')
    fi
    
    if [ -n "$results" ]; then
        count=$(echo "$results" | wc -l)
        case $severity in
            "CRITICAL") 
                CRITICAL_COUNT=$((CRITICAL_COUNT + count))
                FOUND_ITEMS+=("CRITICAL|$desc|$count")
                ;;
            "HIGH") 
                HIGH_COUNT=$((HIGH_COUNT + count))
                FOUND_ITEMS+=("HIGH|$desc|$count")
                ;;
            "MEDIUM") 
                MEDIUM_COUNT=$((MEDIUM_COUNT + count))
                FOUND_ITEMS+=("MEDIUM|$desc|$count")
                ;;
        esac
        echo "" >> "$REPORT_FILE"
        echo "[$severity] $desc" >> "$REPORT_FILE"
        echo "$results" >> "$REPORT_FILE"
    fi
}

show_loading

scan 'x=s=>eval' "Miaus - XOR Decoder (x=s=>eval)" "CRITICAL" "js"
scan 'eval(s.replace' "Miaus - eval+replace" "CRITICAL" "js"
scan 'v="\\u00' "Miaus - Unicode Payload" "CRITICAL" "js"
scan "v='\\\\u00" "Miaus - Unicode Payload" "CRITICAL" "js"
scan 'charCodeAt(0)^3' "Miaus - XOR Key 3" "CRITICAL" "js"
scan 'charCodeAt(0) ^ 3' "Miaus - XOR Key 3" "CRITICAL" "js"
scan '9ns1.com' "Miaus - C2 Domain" "CRITICAL" "all"
scan '9ns1' "Miaus - Reference" "CRITICAL" "all"
scan 'zXeHjj' "Miaus - Endpoint" "CRITICAL" "all"
scan 'globalThis.GlobalState' "Miaus - Persistence" "CRITICAL" "js"
scan 'GlobalState\[' "Miaus - Persistence" "HIGH" "js"
scan '"miaus"' "Miaus - Malware Name" "CRITICAL" "all"
scan "'miaus'" "Miaus - Malware Name" "CRITICAL" "all"

scan 'assert(load(d))' "Cipher - Backdoor Loader" "CRITICAL" "lua"
scan 'assert(load(r))' "Cipher - Backdoor Loader" "CRITICAL" "lua"
scan 'pcall(function() assert(load' "Cipher - Protected Loader" "CRITICAL" "lua"
scan 'helpCode' "Cipher - Signature" "CRITICAL" "all"
scan 'Enchanced_Tabs' "Cipher - Variable" "CRITICAL" "lua"
scan 'random_char' "Cipher - Variable" "HIGH" "lua"
scan 'cipher-panel' "Cipher - C2 Domain" "CRITICAL" "all"
scan 'blum-panel' "Blum - C2 Domain" "CRITICAL" "all"
scan 'ciphercheats' "Cipher - Reference" "CRITICAL" "all"
scan 'keyx.club' "Cipher - C2 Domain" "CRITICAL" "all"
scan 'dark-utilities' "Cipher - C2 Domain" "CRITICAL" "all"

scan '\\x50\\x65\\x72\\x66\\x6f\\x72\\x6d' "Hex - PerformHttpRequest" "HIGH" "lua"
scan '\\x61\\x73\\x73\\x65\\x72\\x74' "Hex - assert" "HIGH" "lua"
scan '\\x6c\\x6f\\x61\\x64' "Hex - load" "HIGH" "lua"
scan 'loadstring' "Lua - loadstring()" "HIGH" "lua"
scan 'RunString' "Lua - RunString()" "HIGH" "lua"
scan 'String.fromCharCode(parseInt' "JS - Unicode Decoding" "HIGH" "js"
scan 'fromCharCode' "JS - Char Conversion" "MEDIUM" "js"
scan 'eval(' "JS - eval()" "HIGH" "js"

hidden=$(find "$SCAN_PATH" -type f \( -name ".*\.lua" -o -name ".*\.js" \) 2>/dev/null | grep -v node_modules | grep -v ".eslint" | grep -v ".prettier" | grep -v ".babel")
if [ -n "$hidden" ]; then
    count=$(echo "$hidden" | wc -l)
    CRITICAL_COUNT=$((CRITICAL_COUNT + count))
    FOUND_ITEMS+=("CRITICAL|Hidden Files|$count")
    echo "" >> "$REPORT_FILE"
    echo "[CRITICAL] Hidden Files" >> "$REPORT_FILE"
    echo "$hidden" >> "$REPORT_FILE"
fi

TOTAL=$((CRITICAL_COUNT + HIGH_COUNT + MEDIUM_COUNT))
echo "" >> "$REPORT_FILE"
echo "=== SCAN SUMMARY ===" >> "$REPORT_FILE"
echo "CRITICAL: $CRITICAL_COUNT" >> "$REPORT_FILE"
echo "HIGH: $HIGH_COUNT" >> "$REPORT_FILE"
echo "MEDIUM: $MEDIUM_COUNT" >> "$REPORT_FILE"
echo "TOTAL DETECTIONS: $TOTAL" >> "$REPORT_FILE"
echo "Scan completed: $(date)" >> "$REPORT_FILE"

clear
echo -e "${CYAN}"
echo "╔═══════════════════════════════════════════════════════════════════╗"
echo "║                    ╦  ╦ ╦╔╗╔╔═╗╔═╗╦ ╦╦╔═╗╦  ╔╦╗                   ║"
echo "║                    ║  ║ ║║║║╠═╣╚═╗╠═╣║║╣ ║   ║║                   ║"
echo "║                    ╩═╝╚═╝╝╚╝╩ ╩╚═╝╩ ╩╩╚═╝╩═╝═╩╝                   ║"
echo "║                                                                   ║"
echo "║                 Advanced Backdoor Detection System                ║"
echo "║                            by Soul <3                             ║"
echo "╚═══════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo ""

if [ $TOTAL -eq 0 ]; then
    echo -e "${GREEN}✅ Scan completed successfully!${NC}"
    echo ""
    echo -e "${GREEN}No threats detected in: $SCAN_PATH${NC}"
else
    echo -e "${RED}⚠️  Scan completed with findings!${NC}"
    echo ""
    
    if [ $CRITICAL_COUNT -gt 0 ]; then
        echo -e "${RED}CRITICAL threats found: $CRITICAL_COUNT${NC}"
    fi
    if [ $HIGH_COUNT -gt 0 ]; then
        echo -e "${YELLOW}HIGH threats found: $HIGH_COUNT${NC}"
    fi
    if [ $MEDIUM_COUNT -gt 0 ]; then
        echo -e "${CYAN}MEDIUM threats found: $MEDIUM_COUNT${NC}"
    fi
    
    echo ""
    echo -e "${YELLOW}Total detections: $TOTAL${NC}"
fi

echo ""
echo -e "${BLUE}Full report saved to: ${YELLOW}$REPORT_FILE${NC}"
echo ""