#!/usr/bin/env bash
#
# aisec-scan installer
# Usage: curl -fsSL https://raw.githubusercontent.com/terichev/aisec-scan/main/install.sh | bash
#
# For security, you can verify the script before running:
#   curl -fsSL https://raw.githubusercontent.com/terichev/aisec-scan/main/install.sh -o install.sh
#   less install.sh  # Review the script
#   bash install.sh
#
set -eo pipefail

REPO="terichev/aisec-scan"
REPO_URL="https://raw.githubusercontent.com/${REPO}/main"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
BINARY_NAME="aisec-scan"
VERSION="2.0.0"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo ""
echo -e "${GREEN}Installing aisec-scan v${VERSION}...${NC}"
echo ""

# Check for curl or wget
if command -v curl &>/dev/null; then
    DOWNLOADER="curl -fsSL"
elif command -v wget &>/dev/null; then
    DOWNLOADER="wget -qO-"
else
    echo -e "${RED}Error: curl or wget required${NC}" >&2
    exit 1
fi

# Create temp directory
TEMP_DIR=$(mktemp -d)
trap 'rm -rf "$TEMP_DIR"' EXIT

echo "Downloading scan.sh..."
$DOWNLOADER "$REPO_URL/scan.sh" > "$TEMP_DIR/$BINARY_NAME"

# Download checksum file if available
echo "Verifying integrity..."
if $DOWNLOADER "$REPO_URL/checksums.sha256" > "$TEMP_DIR/checksums.sha256" 2>/dev/null; then
    # Extract expected checksum for scan.sh
    EXPECTED_CHECKSUM=$(grep "scan.sh" "$TEMP_DIR/checksums.sha256" | cut -d' ' -f1)

    if [[ -n "$EXPECTED_CHECKSUM" ]]; then
        # Calculate actual checksum
        if command -v sha256sum &>/dev/null; then
            ACTUAL_CHECKSUM=$(sha256sum "$TEMP_DIR/$BINARY_NAME" | cut -d' ' -f1)
        elif command -v shasum &>/dev/null; then
            ACTUAL_CHECKSUM=$(shasum -a 256 "$TEMP_DIR/$BINARY_NAME" | cut -d' ' -f1)
        else
            echo -e "${YELLOW}Warning: Cannot verify checksum (sha256sum/shasum not found)${NC}"
            ACTUAL_CHECKSUM=""
        fi

        if [[ -n "$ACTUAL_CHECKSUM" && "$EXPECTED_CHECKSUM" != "$ACTUAL_CHECKSUM" ]]; then
            echo -e "${RED}Error: Checksum verification failed!${NC}" >&2
            echo -e "${RED}Expected: $EXPECTED_CHECKSUM${NC}" >&2
            echo -e "${RED}Actual:   $ACTUAL_CHECKSUM${NC}" >&2
            echo -e "${RED}The file may have been tampered with. Aborting.${NC}" >&2
            exit 1
        elif [[ -n "$ACTUAL_CHECKSUM" ]]; then
            echo -e "${GREEN}Checksum verified.${NC}"
        fi
    else
        echo -e "${YELLOW}Warning: No checksum found for scan.sh${NC}"
    fi
else
    echo -e "${YELLOW}Warning: checksums.sha256 not available, skipping verification${NC}"
fi

# Install
echo "Installing to ${INSTALL_DIR}..."
if [[ -w "$INSTALL_DIR" ]]; then
    mv "$TEMP_DIR/$BINARY_NAME" "$INSTALL_DIR/$BINARY_NAME"
    chmod +x "$INSTALL_DIR/$BINARY_NAME"
else
    echo "Installing to $INSTALL_DIR requires sudo..."
    sudo mv "$TEMP_DIR/$BINARY_NAME" "$INSTALL_DIR/$BINARY_NAME"
    sudo chmod +x "$INSTALL_DIR/$BINARY_NAME"
fi

echo ""
echo -e "${GREEN}aisec-scan installed successfully!${NC}"
echo ""
echo "Usage:"
echo "  aisec-scan              # Scan current directory"
echo "  aisec-scan ~/projects   # Scan specific directory"
echo "  aisec-scan --help       # Show all options"
echo ""
echo -e "Repository: ${YELLOW}https://github.com/${REPO}${NC}"
echo ""
