#!/usr/bin/env bash
#
# aisec-scan - AI IDE Security Scanner
# Detects prompt injection vulnerabilities and malicious configurations
# in AI-powered IDEs and CLI tools.
#
# Supported tools: Cursor, VS Code + Copilot, Claude Code, Claude Desktop,
#                  Kilo Code, Windsurf, Gemini CLI, Amazon Q, Aider
#
# Usage: aisec-scan [OPTIONS] [DIRECTORY]
# Repository: https://github.com/terichev/aisec-scan
# License: MIT
#
set -eo pipefail

VERSION="2.0.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ═══════════════════════════════════════════════════════════════════════════
# Configuration
# ═══════════════════════════════════════════════════════════════════════════

# Colors (disabled with --no-color)
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Counters
CRITICAL_COUNT=0
WARNING_COUNT=0
INFO_COUNT=0
FILES_SCANNED=0

# Options
SCAN_DIR="${PWD}"
OUTPUT_FORMAT="text"
OUTPUT_FILE=""
NO_COLOR=false
QUIET=false
SKIP_NPM=false
SKIP_GLOBAL=false
TOOLS_FILTER=""

# Results storage for JSON/SARIF output
declare -a FINDINGS=()
declare -a DETECTED_TOOLS=()

# ═══════════════════════════════════════════════════════════════════════════
# CVE Database (embedded as plain text for bash 3.x compatibility)
# ═══════════════════════════════════════════════════════════════════════════

# Format: CVE|tool|cvss|description|fixed_version
CVE_DATABASE="
CVE-2025-54135|cursor|8.6|MCP config overwrite (CurXecute)|1.3
CVE-2025-54136|cursor|7.2|MCP trust bypass (MCPoison)|1.3
CVE-2025-59944|cursor|8.1|Case-sensitivity bypass|1.7
CVE-2025-53773|copilot|7.5|YOLO mode activation|latest
CVE-2025-54794|claude|7.8|Path restriction bypass|0.2.111
CVE-2025-54795|claude|7.5|Command injection whitelist bypass|0.2.111
CVE-2025-52882|claude|8.8|WebSocket authentication bypass|latest
TRA-2025-47|windsurf|HIGH|Filename prompt injection|unpatched
"

# Known malicious npm packages
MALICIOUS_NPM_PACKAGES=(
    "sw-cur" "sw-cur1" "aiide-cur" "cursor-ai" "cursor-helper"
    "vscode-cursor" "cursor-tools" "claude-ai-helper" "claude-code-helper"
    "copilot-helper" "ai-code-helper" "windsurf-helper" "kilo-code-helper"
)

# Suspicious patterns in package names
SUSPICIOUS_NPM_PATTERNS=(
    "cursor.*hack" "claude.*inject" "copilot.*patch"
    "vscode.*mod" "ai.*backdoor" "prompt.*inject"
)

# ═══════════════════════════════════════════════════════════════════════════
# Utility Functions
# ═══════════════════════════════════════════════════════════════════════════

# JSON escape function - properly escapes special characters per RFC 8259
json_escape() {
    local str="$1"
    local result=""
    local i char

    for ((i=0; i<${#str}; i++)); do
        char="${str:i:1}"
        case "$char" in
            $'\\') result+='\\' ;;
            '"')  result+='\"' ;;
            $'\n') result+='\n' ;;
            $'\r') result+='\r' ;;
            $'\t') result+='\t' ;;
            $'\b') result+='\b' ;;
            $'\f') result+='\f' ;;
            *)
                # Check for other control characters (U+0000 to U+001F)
                local ord
                ord=$(printf '%d' "'$char" 2>/dev/null || echo 0)
                if [[ $ord -ge 0 && $ord -lt 32 ]]; then
                    # Escape as \uXXXX
                    result+=$(printf '\\u%04x' "$ord")
                else
                    result+="$char"
                fi
                ;;
        esac
    done
    printf '%s' "$result"
}

# Markdown escape function - escapes special characters in table cells
md_escape() {
    local str="$1"
    str="${str//\\/\\\\}"    # backslash first
    str="${str//|/\\|}"      # pipe (table separator)
    str="${str//\`/\\\`}"    # backtick
    str="${str//\*/\\*}"     # asterisk
    str="${str//_/\\_}"      # underscore
    str="${str//\[/\\[}"     # square brackets
    str="${str//\]/\\]}"
    printf '%s' "$str"
}

usage() {
    cat << EOF
${BOLD}aisec-scan${NC} - AI IDE Security Scanner v${VERSION}

${BOLD}USAGE${NC}
    aisec-scan [OPTIONS] [DIRECTORY]

${BOLD}DESCRIPTION${NC}
    Scans for prompt injection vulnerabilities and malicious configurations
    in AI-powered development tools.

${BOLD}OPTIONS${NC}
    -h, --help          Show this help message
    -v, --version       Show version
    -q, --quiet         Minimal output (only critical issues)
    -f, --format FMT    Output format: text, json, sarif, markdown (default: text)
    -o, --output FILE   Write report to file
    --no-color          Disable colored output
    --tools TOOLS       Scan specific tools only (comma-separated)
                        Available: cursor,vscode,claude,kilo,windsurf,gemini,amazonq,aider
    --skip-npm          Skip npm package scanning
    --skip-global       Skip global configuration scanning

${BOLD}EXAMPLES${NC}
    aisec-scan                          # Scan current directory + global configs
    aisec-scan ~/projects               # Scan specific directory
    aisec-scan -f json -o report.json   # JSON report to file
    aisec-scan --tools cursor,claude    # Scan only Cursor and Claude configs
    aisec-scan -f sarif                 # SARIF format for GitHub Security

${BOLD}EXIT CODES${NC}
    0  No issues found
    1  Critical vulnerabilities found
    2  Warnings only (no critical)
    3  Scanner error

${BOLD}MORE INFO${NC}
    Repository: https://github.com/terichev/aisec-scan
    Security:   https://github.com/terichev/aisec-scan/blob/main/SECURITY.md
EOF
}

log_critical() {
    ((CRITICAL_COUNT++))
    if [[ "$OUTPUT_FORMAT" == "text" ]] && [[ "$QUIET" == false ]]; then
        echo -e "${RED}[CRITICAL]${NC} $1"
    fi
    FINDINGS+=("critical|$1|$2|$3")
}

log_warning() {
    ((WARNING_COUNT++))
    if [[ "$OUTPUT_FORMAT" == "text" ]] && [[ "$QUIET" == false ]]; then
        echo -e "${YELLOW}[WARNING]${NC} $1"
    fi
    FINDINGS+=("warning|$1|$2|$3")
}

log_info() {
    ((INFO_COUNT++))
    if [[ "$OUTPUT_FORMAT" == "text" ]] && [[ "$QUIET" == false ]]; then
        echo -e "${BLUE}[INFO]${NC} $1"
    fi
}

log_ok() {
    if [[ "$OUTPUT_FORMAT" == "text" ]] && [[ "$QUIET" == false ]]; then
        echo -e "${GREEN}[OK]${NC} $1"
    fi
}

section() {
    if [[ "$OUTPUT_FORMAT" == "text" ]] && [[ "$QUIET" == false ]]; then
        echo ""
        echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${CYAN}${BOLD}$1${NC}"
        echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    fi
}

# ═══════════════════════════════════════════════════════════════════════════
# Platform Detection
# ═══════════════════════════════════════════════════════════════════════════

detect_platform() {
    case "$(uname -s)" in
        Darwin)
            PLATFORM="macos"
            VSCODE_GLOBAL="$HOME/Library/Application Support/Code/User"
            CLAUDE_DESKTOP="$HOME/Library/Application Support/Claude"
            KILO_GLOBAL="$HOME/Library/Application Support/Code/User/globalStorage/kilocode.kilo-code"
            ;;
        Linux)
            PLATFORM="linux"
            VSCODE_GLOBAL="$HOME/.config/Code/User"
            CLAUDE_DESKTOP="$HOME/.config/claude"
            KILO_GLOBAL="$HOME/.config/Code/User/globalStorage/kilocode.kilo-code"
            ;;
        MINGW*|CYGWIN*|MSYS*)
            PLATFORM="windows"
            VSCODE_GLOBAL="$APPDATA/Code/User"
            CLAUDE_DESKTOP="$APPDATA/Claude"
            KILO_GLOBAL="$APPDATA/Code/User/globalStorage/kilocode.kilo-code"
            ;;
        *)
            PLATFORM="unknown"
            VSCODE_GLOBAL="$HOME/.config/Code/User"
            CLAUDE_DESKTOP="$HOME/.config/claude"
            KILO_GLOBAL=""
            ;;
    esac
}

# ═══════════════════════════════════════════════════════════════════════════
# Tool Detection
# ═══════════════════════════════════════════════════════════════════════════

detect_tools() {
    local tools=()

    # Check CLI commands
    command -v cursor &>/dev/null && tools+=("cursor")
    command -v claude &>/dev/null && tools+=("claude")
    command -v code &>/dev/null && tools+=("vscode")
    command -v windsurf &>/dev/null && tools+=("windsurf")
    command -v gemini &>/dev/null && tools+=("gemini")
    command -v q &>/dev/null && tools+=("amazonq")
    command -v aider &>/dev/null && tools+=("aider")

    # Check config directories
    [[ -d "$HOME/.cursor" ]] && [[ ! " ${tools[*]} " =~ " cursor " ]] && tools+=("cursor")
    [[ -d "$HOME/.claude" ]] && [[ ! " ${tools[*]} " =~ " claude " ]] && tools+=("claude")
    [[ -d "$CLAUDE_DESKTOP" ]] && [[ ! " ${tools[*]} " =~ " claude-desktop " ]] && tools+=("claude-desktop")
    [[ -d "$KILO_GLOBAL" ]] && tools+=("kilo")

    DETECTED_TOOLS=("${tools[@]}")
}

get_tool_version() {
    local tool="$1"
    case "$tool" in
        cursor)
            cursor --version 2>/dev/null | head -1 || echo "unknown"
            ;;
        claude)
            claude --version 2>/dev/null | head -1 || echo "unknown"
            ;;
        vscode)
            code --version 2>/dev/null | head -1 || echo "unknown"
            ;;
        *)
            echo "unknown"
            ;;
    esac
}

should_scan_tool() {
    local tool="$1"
    if [[ -z "$TOOLS_FILTER" ]]; then
        return 0
    fi
    [[ ",$TOOLS_FILTER," == *",$tool,"* ]]
}

# ═══════════════════════════════════════════════════════════════════════════
# Security Checks
# ═══════════════════════════════════════════════════════════════════════════

# Check for hidden Unicode characters (Zero-Width Space, ZWNJ, ZWJ, etc.)
# Supports xxd, od, and hexdump for cross-platform compatibility
check_unicode_injection() {
    local file="$1"
    ((FILES_SCANNED++))

    # UTF-8 sequences for zero-width characters:
    # ZWSP (U+200B): e2 80 8b
    # ZWNJ (U+200C): e2 80 8c
    # ZWJ (U+200D): e2 80 8d
    # LRM/RLM (U+200E/F): e2 80 8e/8f
    # Bidi markers (U+202A-202E): e2 80 aa-ae

    local has_unicode=false
    local hex_content=""

    # Get hex dump using available tool
    if command -v xxd &>/dev/null; then
        hex_content=$(xxd -p "$file" 2>/dev/null | tr -d '\n')
    elif command -v hexdump &>/dev/null; then
        # hexdump is available on macOS by default
        hex_content=$(hexdump -ve '1/1 "%02x"' "$file" 2>/dev/null)
    elif command -v od &>/dev/null; then
        hex_content=$(od -An -tx1 "$file" 2>/dev/null | tr -d ' \n')
    fi

    if [[ -n "$hex_content" ]]; then
        # Check for UTF-8 sequences of zero-width characters
        # e2808b = ZWSP, e2808c = ZWNJ, e2808d = ZWJ
        # e2808e = LRM, e2808f = RLM
        # e280aa-e280ae = Bidi markers
        if echo "$hex_content" | grep -qE 'e2808[bcdef]|e280a[abcde]'; then
            has_unicode=true
        fi
    fi

    if [[ "$has_unicode" == true ]]; then
        log_critical "Unicode injection detected" "$file" "Hidden characters may contain malicious AI instructions"
    fi
    return 0
}

# Check MCP configuration for suspicious servers
check_mcp_config() {
    local file="$1"
    [[ ! -f "$file" ]] && return 0
    ((FILES_SCANNED++))

    # Check for suspicious commands in MCP servers
    if grep -qE '(curl |wget |nc |netcat|bash -i|/dev/tcp|reverse.shell|eval\(|exec\()' "$file" 2>/dev/null; then
        log_critical "Suspicious command in MCP config" "$file" "CVE-2025-54135: Potential RCE via MCP server"
    fi

    # Check for unknown MCP servers
    local known_mcp="playwright|filesystem|github|slack|postgres|sqlite|puppeteer|brave-search|fetch|memory|sequential-thinking"
    if grep -qE '"command"' "$file" 2>/dev/null; then
        local servers
        servers=$(grep -oE '"[a-zA-Z0-9_-]+"\s*:\s*\{' "$file" | grep -v "mcpServers\|args\|env" | tr -d '": {' | tr '\n' ' ' || true)
        for server in $servers; do
            if ! echo "$server" | grep -qiE "^($known_mcp)$"; then
                log_warning "Unknown MCP server: $server" "$file" "Verify this is a legitimate MCP server"
            fi
        done
    fi
    return 0
}

# Check for auto-run tasks (Workspace Trust bypass)
check_tasks_autorun() {
    local file="$1"
    [[ ! -f "$file" ]] && return 0
    ((FILES_SCANNED++))

    if grep -q '"runOn".*"folderOpen"' "$file" 2>/dev/null; then
        log_critical "Auto-run task on folder open" "$file" "Commands execute without user consent"
    fi

    if grep -qE '(curl.*http|wget |nc -|bash -i|/dev/tcp)' "$file" 2>/dev/null; then
        log_warning "Suspicious command in tasks.json" "$file" "Review task commands for safety"
    fi
    return 0
}

# Check settings for dangerous configurations
check_settings() {
    local file="$1"
    [[ ! -f "$file" ]] && return 0
    ((FILES_SCANNED++))

    local dangerous=(
        'autoApprove.*true'
        'autoRun.*true'
        '"yolo".*true'
        'workspace.trust.enabled.*false'
        'security.workspace.trust.enabled.*false'
        'chat.tools.autoApprove.*true'
    )

    for pattern in "${dangerous[@]}"; do
        if grep -qiE "$pattern" "$file" 2>/dev/null; then
            log_critical "Dangerous setting: $pattern" "$file" "AI commands may execute without approval"
        fi
    done
}

# Check npm packages for known malicious packages
check_npm_package() {
    local file="$1"
    [[ ! -f "$file" ]] && return 0
    ((FILES_SCANNED++))

    for pkg in "${MALICIOUS_NPM_PACKAGES[@]}"; do
        if grep -q "\"$pkg\"" "$file" 2>/dev/null; then
            log_critical "Malicious npm package: $pkg" "$file" "This package is known AI IDE malware"
        fi
    done

    for pattern in "${SUSPICIOUS_NPM_PATTERNS[@]}"; do
        local found
        found=$(grep -oiE "\"$pattern[^\"]*\"" "$file" 2>/dev/null | head -1 || true)
        if [[ -n "$found" ]]; then
            log_warning "Suspicious package name: $found" "$file" "Verify package legitimacy"
        fi
    done

    # Check postinstall scripts
    if grep -qE '"(preinstall|postinstall)"' "$file" 2>/dev/null; then
        if grep -A5 '"postinstall"' "$file" 2>/dev/null | grep -qiE '(curl|wget|\.cursor|\.claude|\.vscode)'; then
            log_critical "Suspicious postinstall script" "$file" "Script may modify IDE configs"
        fi
    fi
}

# Check global npm packages
check_global_npm() {
    command -v npm &>/dev/null || return 0

    local packages
    packages=$(npm list -g --depth=0 2>/dev/null | tail -n +2 || true)

    for pkg in "${MALICIOUS_NPM_PACKAGES[@]}"; do
        if echo "$packages" | grep -q "$pkg"; then
            log_critical "Malicious GLOBAL npm package: $pkg" "npm global" "Run: npm uninstall -g $pkg"
        fi
    done
}

# ═══════════════════════════════════════════════════════════════════════════
# Output Formatters
# ═══════════════════════════════════════════════════════════════════════════

output_text_header() {
    echo ""
    echo -e "${BLUE}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║${NC}           ${BOLD}AI IDE Security Scanner v${VERSION}${NC}                      ${BLUE}║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${BOLD}Scan:${NC} $SCAN_DIR"
    echo -e "${BOLD}Date:${NC} $(date '+%Y-%m-%d %H:%M:%S')"
    echo -e "${BOLD}Platform:${NC} $PLATFORM"
}

output_text_tools() {
    section "DETECTED TOOLS"
    for tool in "${DETECTED_TOOLS[@]}"; do
        local version
        version=$(get_tool_version "$tool")
        echo -e "  ${GREEN}✓${NC} $tool $version"
    done
    if [[ ${#DETECTED_TOOLS[@]} -eq 0 ]]; then
        echo "  No AI IDE tools detected"
    fi
}

output_text_summary() {
    section "SCAN SUMMARY"
    echo ""
    echo -e "  Files scanned: ${BOLD}$FILES_SCANNED${NC}"
    echo ""
    if [[ $CRITICAL_COUNT -gt 0 ]]; then
        echo -e "  ${RED}[CRITICAL]${NC} $CRITICAL_COUNT issues found"
    else
        echo -e "  ${GREEN}[CRITICAL]${NC} 0 issues"
    fi
    if [[ $WARNING_COUNT -gt 0 ]]; then
        echo -e "  ${YELLOW}[WARNING]${NC}  $WARNING_COUNT issues found"
    else
        echo -e "  ${GREEN}[WARNING]${NC}  0 issues"
    fi
    echo ""

    if [[ $CRITICAL_COUNT -gt 0 ]]; then
        echo -e "${RED}══════════════════════════════════════════════════════════════════${NC}"
        echo -e "${RED}  CRITICAL VULNERABILITIES FOUND! Immediate action required.${NC}"
        echo -e "${RED}══════════════════════════════════════════════════════════════════${NC}"
    elif [[ $WARNING_COUNT -gt 0 ]]; then
        echo -e "${YELLOW}Warnings found. Review recommended.${NC}"
    else
        echo -e "${GREEN}══════════════════════════════════════════════════════════════════${NC}"
        echo -e "${GREEN}  No security issues detected. Configuration is secure.${NC}"
        echo -e "${GREEN}══════════════════════════════════════════════════════════════════${NC}"
    fi
}

output_json() {
    local issues=()
    local first_issue=true
    for finding in "${FINDINGS[@]}"; do
        IFS='|' read -r severity message file details <<< "$finding"
        # Properly escape all values for JSON
        local esc_message esc_file esc_details
        esc_message=$(json_escape "$message")
        esc_file=$(json_escape "$file")
        esc_details=$(json_escape "$details")
        issues+=("{\"severity\":\"$severity\",\"message\":\"$esc_message\",\"file\":\"$esc_file\",\"details\":\"$esc_details\"}")
    done

    local tools_json=""
    for tool in "${DETECTED_TOOLS[@]}"; do
        [[ -n "$tools_json" ]] && tools_json+=","
        tools_json+="\"$(json_escape "$tool")\""
    done

    local esc_scan_dir
    esc_scan_dir=$(json_escape "$SCAN_DIR")

    cat << EOF
{
  "version": "$VERSION",
  "scan_directory": "$esc_scan_dir",
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "platform": "$PLATFORM",
  "detected_tools": [$tools_json],
  "summary": {
    "files_scanned": $FILES_SCANNED,
    "critical": $CRITICAL_COUNT,
    "warnings": $WARNING_COUNT
  },
  "issues": [$(IFS=,; echo "${issues[*]}")]
}
EOF
}

output_sarif() {
    local results=()
    local idx=0
    local rule_ids=("UNICODE_INJECTION" "MCP_SUSPICIOUS_CMD" "MCP_UNKNOWN_SERVER" "TASKS_AUTORUN" "DANGEROUS_SETTING" "MALICIOUS_NPM" "SUSPICIOUS_NPM" "POSTINSTALL_SUSPICIOUS")

    for finding in "${FINDINGS[@]}"; do
        IFS='|' read -r severity message file details <<< "$finding"
        local level="warning"
        [[ "$severity" == "critical" ]] && level="error"

        # Properly escape all values for JSON
        local esc_message esc_file esc_details
        esc_message=$(json_escape "$message")
        esc_file=$(json_escape "$file")
        esc_details=$(json_escape "$details")

        # Determine rule ID based on message content
        local rule_id="AISEC-GENERIC"
        case "$message" in
            *"Unicode"*) rule_id="AISEC-UNICODE" ;;
            *"MCP"*"command"*|*"Suspicious command"*) rule_id="AISEC-MCP-CMD" ;;
            *"Unknown MCP"*) rule_id="AISEC-MCP-UNKNOWN" ;;
            *"Auto-run"*) rule_id="AISEC-AUTORUN" ;;
            *"Dangerous setting"*) rule_id="AISEC-SETTINGS" ;;
            *"Malicious"*"npm"*) rule_id="AISEC-NPM-MALICIOUS" ;;
            *"Suspicious package"*) rule_id="AISEC-NPM-SUSPICIOUS" ;;
            *"postinstall"*) rule_id="AISEC-POSTINSTALL" ;;
        esac

        results+=("{
          \"ruleId\": \"$rule_id\",
          \"level\": \"$level\",
          \"message\": {\"text\": \"$esc_message: $esc_details\"},
          \"locations\": [{
            \"physicalLocation\": {
              \"artifactLocation\": {\"uri\": \"$esc_file\"}
            }
          }]
        }")
        ((idx++))
    done

    cat << EOF
{
  "\$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "aisec-scan",
        "version": "$VERSION",
        "informationUri": "https://github.com/terichev/aisec-scan",
        "rules": [
          {"id": "AISEC-UNICODE", "shortDescription": {"text": "Unicode Injection"}, "helpUri": "https://github.com/terichev/aisec-scan#unicode-injection"},
          {"id": "AISEC-MCP-CMD", "shortDescription": {"text": "Suspicious MCP Command"}, "helpUri": "https://github.com/terichev/aisec-scan#mcp-attacks"},
          {"id": "AISEC-MCP-UNKNOWN", "shortDescription": {"text": "Unknown MCP Server"}, "helpUri": "https://github.com/terichev/aisec-scan#mcp-attacks"},
          {"id": "AISEC-AUTORUN", "shortDescription": {"text": "Task Auto-Run"}, "helpUri": "https://github.com/terichev/aisec-scan#workspace-trust"},
          {"id": "AISEC-SETTINGS", "shortDescription": {"text": "Dangerous Setting"}, "helpUri": "https://github.com/terichev/aisec-scan#workspace-trust"},
          {"id": "AISEC-NPM-MALICIOUS", "shortDescription": {"text": "Malicious NPM Package"}, "helpUri": "https://github.com/terichev/aisec-scan#supply-chain"},
          {"id": "AISEC-NPM-SUSPICIOUS", "shortDescription": {"text": "Suspicious NPM Package"}, "helpUri": "https://github.com/terichev/aisec-scan#supply-chain"},
          {"id": "AISEC-POSTINSTALL", "shortDescription": {"text": "Suspicious Postinstall"}, "helpUri": "https://github.com/terichev/aisec-scan#supply-chain"},
          {"id": "AISEC-GENERIC", "shortDescription": {"text": "Security Issue"}, "helpUri": "https://github.com/terichev/aisec-scan"}
        ]
      }
    },
    "results": [$(IFS=,; echo "${results[*]}")]
  }]
}
EOF
}

output_markdown() {
    cat << EOF
# AI IDE Security Scan Report

**Scanner:** aisec-scan v${VERSION}
**Date:** $(date '+%Y-%m-%d %H:%M:%S')
**Directory:** \`$SCAN_DIR\`
**Platform:** $PLATFORM

## Summary

| Metric | Count |
|--------|-------|
| Files Scanned | $FILES_SCANNED |
| Critical Issues | $CRITICAL_COUNT |
| Warnings | $WARNING_COUNT |

## Detected Tools

EOF
    for tool in "${DETECTED_TOOLS[@]}"; do
        echo "- $tool"
    done

    if [[ ${#FINDINGS[@]} -gt 0 ]]; then
        echo ""
        echo "## Issues Found"
        echo ""
        echo "| Severity | Message | File | Details |"
        echo "|----------|---------|------|---------|"
        for finding in "${FINDINGS[@]}"; do
            IFS='|' read -r severity message file details <<< "$finding"
            # Escape pipe characters in table cells
            local esc_message esc_file esc_details
            esc_message=$(md_escape "$message")
            esc_file=$(md_escape "$file")
            esc_details=$(md_escape "$details")
            echo "| $severity | $esc_message | \`$esc_file\` | $esc_details |"
        done
    fi

    echo ""
    echo "---"
    echo "*Generated by [aisec-scan](https://github.com/terichev/aisec-scan)*"
}

# ═══════════════════════════════════════════════════════════════════════════
# Main Scanning Logic
# ═══════════════════════════════════════════════════════════════════════════

scan_global_configs() {
    [[ "$SKIP_GLOBAL" == true ]] && return 0

    section "1. Global MCP Configurations"

    # Check Cursor MCP
    if should_scan_tool "cursor"; then
        [[ -f "$HOME/.cursor/mcp.json" ]] && check_mcp_config "$HOME/.cursor/mcp.json"
    fi

    # Check VS Code MCP
    if should_scan_tool "vscode"; then
        [[ -f "$HOME/.vscode/mcp.json" ]] && check_mcp_config "$HOME/.vscode/mcp.json"
    fi

    # Check Claude Desktop MCP
    if should_scan_tool "claude"; then
        [[ -n "$CLAUDE_DESKTOP" && -f "$CLAUDE_DESKTOP/claude_desktop_config.json" ]] && check_mcp_config "$CLAUDE_DESKTOP/claude_desktop_config.json"
    fi

    # Check Kilo Code MCP
    if should_scan_tool "kilo"; then
        [[ -n "$KILO_GLOBAL" && -f "$KILO_GLOBAL/settings/mcp_settings.json" ]] && check_mcp_config "$KILO_GLOBAL/settings/mcp_settings.json"
    fi

    log_ok "Global MCP configs checked"

    section "2. Global Settings"

    # Check VS Code settings
    if should_scan_tool "vscode"; then
        [[ -n "$VSCODE_GLOBAL" && -f "$VSCODE_GLOBAL/settings.json" ]] && check_settings "$VSCODE_GLOBAL/settings.json"
    fi

    # Check Cursor settings
    if should_scan_tool "cursor"; then
        [[ -f "$HOME/.cursor/settings.json" ]] && check_settings "$HOME/.cursor/settings.json"
    fi

    # Check Claude settings
    if should_scan_tool "claude"; then
        [[ -f "$HOME/.claude/settings.json" ]] && check_settings "$HOME/.claude/settings.json"
    fi

    log_ok "Global settings checked"
}

scan_project_configs() {
    section "3. Project MCP Configurations"

    while IFS= read -r -d '' file; do
        check_mcp_config "$file"
    done < <(find "${SCAN_DIR}" -name "mcp.json" -type f -not -path "*/node_modules/*" -print0 2>/dev/null || true)
    log_ok "Project MCP configs checked"

    section "4. Rules Files (Unicode Injection)"

    # .cursorrules
    while IFS= read -r -d '' file; do
        check_unicode_injection "$file"
    done < <(find "${SCAN_DIR}" -name ".cursorrules" -type f -print0 2>/dev/null || true)

    # .windsurfrules
    while IFS= read -r -d '' file; do
        check_unicode_injection "$file"
    done < <(find "${SCAN_DIR}" -name ".windsurfrules" -type f -print0 2>/dev/null || true)

    # .cursor/rules/
    while IFS= read -r -d '' file; do
        check_unicode_injection "$file"
    done < <(find "${SCAN_DIR}" -path "*/.cursor/rules/*" -type f -print0 2>/dev/null || true)

    # .claude/commands/
    while IFS= read -r -d '' file; do
        check_unicode_injection "$file"
    done < <(find "${SCAN_DIR}" -path "*/.claude/commands/*.md" -type f -print0 2>/dev/null || true)

    # .kilocode/
    while IFS= read -r -d '' file; do
        check_unicode_injection "$file"
    done < <(find "${SCAN_DIR}" -path "*/.kilocode/*" -name "*.md" -type f -print0 2>/dev/null || true)

    # GEMINI.md
    while IFS= read -r -d '' file; do
        check_unicode_injection "$file"
    done < <(find "${SCAN_DIR}" -name "GEMINI.md" -type f -print0 2>/dev/null || true)

    # .github/copilot-instructions.md
    while IFS= read -r -d '' file; do
        check_unicode_injection "$file"
    done < <(find "${SCAN_DIR}" -name "copilot-instructions.md" -type f -print0 2>/dev/null || true)

    log_ok "Rules files checked"

    section "5. VS Code Tasks (Auto-Run)"

    while IFS= read -r -d '' file; do
        check_tasks_autorun "$file"
    done < <(find "${SCAN_DIR}" -path "*/.vscode/tasks.json" -type f -print0 2>/dev/null || true)
    log_ok "Tasks files checked"

    section "6. Project Settings"

    while IFS= read -r -d '' file; do
        check_settings "$file"
    done < <(find "${SCAN_DIR}" -path "*/.vscode/settings.json" -type f -not -path "*/node_modules/*" -print0 2>/dev/null || true)
    log_ok "Project settings checked"
}

scan_npm_packages() {
    [[ "$SKIP_NPM" == true ]] && return 0

    section "7. NPM Packages (Supply Chain)"

    log_info "Checking global npm packages..."
    check_global_npm

    log_info "Checking project package.json files..."
    local count=0
    while IFS= read -r -d '' file; do
        check_npm_package "$file"
        ((count++))
    done < <(find "${SCAN_DIR}" -name "package.json" -type f -not -path "*/node_modules/*" -print0 2>/dev/null || true)
    log_ok "NPM packages checked: $count files"
}

# ═══════════════════════════════════════════════════════════════════════════
# Main Entry Point
# ═══════════════════════════════════════════════════════════════════════════

main() {
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                usage
                exit 0
                ;;
            -v|--version)
                echo "aisec-scan v$VERSION"
                exit 0
                ;;
            -q|--quiet)
                QUIET=true
                shift
                ;;
            -f|--format)
                OUTPUT_FORMAT="$2"
                shift 2
                ;;
            -o|--output)
                OUTPUT_FILE="$2"
                shift 2
                ;;
            --no-color)
                NO_COLOR=true
                RED="" GREEN="" YELLOW="" BLUE="" CYAN="" BOLD="" NC=""
                shift
                ;;
            --tools)
                TOOLS_FILTER="$2"
                shift 2
                ;;
            --skip-npm)
                SKIP_NPM=true
                shift
                ;;
            --skip-global)
                SKIP_GLOBAL=true
                shift
                ;;
            -*)
                echo "Unknown option: $1" >&2
                usage
                exit 3
                ;;
            *)
                SCAN_DIR="$1"
                shift
                ;;
        esac
    done

    # Validate format
    case "$OUTPUT_FORMAT" in
        text|json|sarif|markdown) ;;
        *)
            echo "Invalid format: $OUTPUT_FORMAT" >&2
            exit 3
            ;;
    esac

    # Validate directory
    if [[ ! -d "$SCAN_DIR" ]]; then
        echo "Directory not found: $SCAN_DIR" >&2
        exit 3
    fi

    # Initialize
    detect_platform
    detect_tools

    # Run scans
    if [[ "$OUTPUT_FORMAT" == "text" ]]; then
        output_text_header
        output_text_tools
    fi

    scan_global_configs
    scan_project_configs
    scan_npm_packages

    # Output results
    case "$OUTPUT_FORMAT" in
        text)
            output_text_summary
            ;;
        json)
            if [[ -n "$OUTPUT_FILE" ]]; then
                output_json > "$OUTPUT_FILE"
                echo "Report written to: $OUTPUT_FILE"
            else
                output_json
            fi
            ;;
        sarif)
            if [[ -n "$OUTPUT_FILE" ]]; then
                output_sarif > "$OUTPUT_FILE"
                echo "SARIF report written to: $OUTPUT_FILE"
            else
                output_sarif
            fi
            ;;
        markdown)
            if [[ -n "$OUTPUT_FILE" ]]; then
                output_markdown > "$OUTPUT_FILE"
                echo "Markdown report written to: $OUTPUT_FILE"
            else
                output_markdown
            fi
            ;;
    esac

    # Exit code
    if [[ $CRITICAL_COUNT -gt 0 ]]; then
        exit 1
    elif [[ $WARNING_COUNT -gt 0 ]]; then
        exit 2
    else
        exit 0
    fi
}

main "$@"
