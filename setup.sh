#!/bin/bash
# Setup script for Local Albert Activation Server
# Installs dependencies and configures the environment

set -e

echo "=== Local Albert Activation Server Setup ==="

# Check OS
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
else
    echo "Unsupported OS: $OSTYPE"
    exit 1
fi

echo "Detected OS: $OS"

# Install system dependencies
install_system_deps() {
    echo "Installing system dependencies..."
    
    if [[ "$OS" == "linux" ]]; then
        if command -v apt-get &> /dev/null; then
            sudo apt-get update
            sudo apt-get install -y \
                python3 python3-pip python3-venv \
                libimobiledevice6 libimobiledevice-utils \
                libplist3 libusbmuxd6 usbmuxd \
                libcurl4-openssl-dev libssl-dev \
                pkg-config build-essential \
                mitmproxy
        elif command -v dnf &> /dev/null; then
            sudo dnf install -y \
                python3 python3-pip \
                libimobiledevice libimobiledevice-utils \
                libplist libusbmuxd usbmuxd \
                libcurl-devel openssl-devel \
                pkg-config gcc gcc-c++ make \
                mitmproxy
        elif command -v pacman &> /dev/null; then
            sudo pacman -S --needed \
                python python-pip \
                libimobiledevice libplist libusbmuxd usbmuxd \
                curl openssl \
                base-devel \
                mitmproxy
        else
            echo "Unsupported package manager. Please install dependencies manually."
        fi
    elif [[ "$OS" == "macos" ]]; then
        if command -v brew &> /dev/null; then
            brew install python3 libimobiledevice usbmuxd mitmproxy
        else
            echo "Homebrew not found. Please install Homebrew first."
            exit 1
        fi
    fi
}

# Create Python virtual environment
setup_venv() {
    echo "Setting up Python virtual environment..."
    python3 -m venv venv
    source venv/bin/activate
    pip install --upgrade pip
    pip install -r requirements.txt
}

# Generate SSL certificates for HTTPS
generate_ssl_certs() {
    echo "Generating SSL certificates..."
    mkdir -p certs
    
    if [[ ! -f certs/server.crt || ! -f certs/server.key ]]; then
        openssl req -x509 -newkey rsa:2048 -keyout certs/server.key -out certs/server.crt \
            -days 365 -nodes -subj "/CN=albert.local/O=Local Albert Server"
        echo "SSL certificates generated in certs/"
    else
        echo "SSL certificates already exist"
    fi
}

# Create host entries for local Albert server
setup_hosts() {
    echo "Setting up /etc/hosts entries..."
    echo ""
    echo "Add the following to /etc/hosts (requires sudo):"
    echo "127.0.0.1    albert.apple.com"
    echo "127.0.0.1    gs.apple.com"
    echo "127.0.0.1    osrecovery.apple.com"
    echo "127.0.0.1    appldnld.apple.com"
    echo "127.0.0.1    mesu.apple.com"
    echo ""
    read -p "Add entries to /etc/hosts now? (y/N) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        sudo sh -c 'cat >> /etc/hosts << EOF
# Local Albert Activation Server
127.0.0.1    albert.apple.com
127.0.0.1    gs.apple.com
127.0.0.1    osrecovery.apple.com
127.0.0.1    appldnld.apple.com
127.0.0.1    mesu.apple.com
EOF'
        echo "Host entries added"
    fi
}

# Create systemd service (Linux only)
create_systemd_service() {
    if [[ "$OS" == "linux" ]]; then
        echo "Creating systemd service..."
        SERVICE_FILE="/etc/systemd/system/albert-server.service"
        CURRENT_DIR=$(pwd)
        USER=$(whoami)
        
        sudo tee $SERVICE_FILE > /dev/null << EOF
[Unit]
Description=Local Albert Activation Server
After=network.target usbmuxd.service

[Service]
Type=simple
User=$USER
WorkingDirectory=$CURRENT_DIR
Environment=PATH=$CURRENT_DIR/venv/bin:/usr/local/bin:/usr/bin:/bin
ExecStart=$CURRENT_DIR/venv/bin/python albert_server.py --host 0.0.0.0 --port 8080 --ssl-cert $CURRENT_DIR/certs/server.crt --ssl-key $CURRENT_DIR/certs/server.key
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
        
        sudo systemctl daemon-reload
        echo "Systemd service created at $SERVICE_FILE"
        echo "Enable with: sudo systemctl enable albert-server"
        echo "Start with: sudo systemctl start albert-server"
    fi
}

# Create launchd plist (macOS only)
create_launchd_plist() {
    if [[ "$OS" == "macos" ]]; then
        echo "Creating launchd plist..."
        PLIST_FILE="$HOME/Library/LaunchAgents/com.local.albert-server.plist"
        CURRENT_DIR=$(pwd)
        
        cat > $PLIST_FILE << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.local.albert-server</string>
    <key>ProgramArguments</key>
    <array>
        <string>$CURRENT_DIR/venv/bin/python</string>
        <string>$CURRENT_DIR/albert_server.py</string>
        <string>--host</string>
        <string>0.0.0.0</string>
        <string>--port</string>
        <string>8080</string>
        <string>--ssl-cert</string>
        <string>$CURRENT_DIR/certs/server.crt</string>
        <string>--ssl-key</string>
        <string>$CURRENT_DIR/certs/server.key</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>WorkingDirectory</key>
    <string>$CURRENT_DIR</string>
    <key>StandardOutPath</key>
    <string>$CURRENT_DIR/logs/albert-server.log</string>
    <key>StandardErrorPath</key>
    <string>$CURRENT_DIR/logs/albert-server-error.log</string>
</dict>
</plist>
EOF
        
        mkdir -p logs
        echo "Launchd plist created at $PLIST_FILE"
        echo "Load with: launchctl load $PLIST_FILE"
    fi
}

# Main setup flow
main() {
    install_system_deps
    setup_venv
    generate_ssl_certs
    setup_hosts
    
    if [[ "$OS" == "linux" ]]; then
        create_systemd_service
    elif [[ "$OS" == "macos" ]]; then
        create_launchd_plist
    fi
    
    echo ""
    echo "=== Setup Complete ==="
    echo ""
    echo "To start the server manually:"
    echo "  source venv/bin/activate"
    echo "  python albert_server.py --host 0.0.0.0 --port 8080 --ssl-cert certs/server.crt --ssl-key certs/server.key"
    echo ""
    echo "To start the mitmproxy for firmware restore:"
    echo "  mitmproxy -s firmware_restore_proxy.py --set block_global=false"
    echo ""
    echo "To activate a device:"
    echo "  python activate_device.py --albert-url https://127.0.0.1:8080"
    echo ""
    echo "Note: For HTTPS, you'll need to trust the self-signed certificate on the device."
    echo "Or use HTTP with --host 0.0.0.0 --port 8080 (no SSL args)"
}

main "$@"