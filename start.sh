#!/bin/bash
# Start script for Local Albert Activation Server and Proxy - FIXED
# Fixes port conflict (8080 busy -> use 18090), correct health checks, env handling
set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'
log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# FIXED: Host port 8080 is occupied by another service (nginx/fastapi on this host).
# Use 18090 for HTTP and 18443 for HTTPS which are free per ss scan.
ALBERT_HTTP_PORT=${ALBERT_HTTP_PORT:-18090}
ALBERT_HTTPS_PORT=${ALBERT_HTTPS_PORT:-18443}
MITMPROXY_PORT=${MITMPROXY_PORT:-8082}
MITMPROXY_WEB_PORT=${MITMPROXY_WEB_PORT:-8081}
# Prod mode uses gunicorn (default), dev uses python dev server
ALBERT_MODE=${ALBERT_MODE:-prod}

if [[ ! -d "venv" ]]; then
    log_warn "Virtual environment not found. Running setup..."
    ./setup.sh
fi
mkdir -p logs
./scripts/cleanup_logs.sh 2>/dev/null || true
source venv/bin/activate

# Risk gate: no bypass without ALBERT_ACCEPT_RISK=1 (see SECURITY.md, NOTICE)
check_risk_gate() {
    if [[ "${ALBERT_ACCEPT_RISK:-0}" != "1" && "${1:-}" != "--allow-no-risk" ]]; then
        log_error "ALBERT_ACCEPT_RISK must be 1 to start (see SECURITY.md, NOTICE)."
        log_error "Set ALBERT_ACCEPT_RISK=1 in .env or environment, or run with --allow-no-risk for lab-only."
        # also check .env file
        if [[ -f .env ]] && grep -q "^ALBERT_ACCEPT_RISK=1" .env; then
            log_info ".env contains ALBERT_ACCEPT_RISK=1 — continuing"
            return 0
        fi
        return 1
    fi
    return 0
}

# ---- Albert start helpers ----
start_albert_dev() {
    log_info "Starting Albert server (DEV) on port $ALBERT_HTTP_PORT (HTTP)..."
    pkill -f "albert_server.py.*$ALBERT_HTTP_PORT" 2>/dev/null || true
    if [[ -f "certs/server.crt" && -f "certs/server.key" ]]; then
        log_info "SSL certs found, starting HTTPS on $ALBERT_HTTPS_PORT as well..."
        python albert_server.py --host "${ALBERT_HOST:-127.0.0.1}" --port $ALBERT_HTTP_PORT --no-debug > logs/albert.log 2>&1 &
        ALBERT_PID=$!
        echo $ALBERT_PID > .albert.pid
        log_info "Albert HTTP (dev) started (PID: $ALBERT_PID) -> http://127.0.0.1:$ALBERT_HTTP_PORT"
        python albert_server.py --host "${ALBERT_HOST:-127.0.0.1}" --port $ALBERT_HTTPS_PORT --ssl-cert certs/server.crt --ssl-key certs/server.key --no-debug > logs/albert-https.log 2>&1 &
        ALBERT_HTTPS_PID=$!
        echo $ALBERT_HTTPS_PID > .albert-https.pid
        log_info "Albert HTTPS (dev) started (PID: $ALBERT_HTTPS_PID) -> https://127.0.0.1:$ALBERT_HTTPS_PORT"
    else
        log_warn "SSL certificates not found. Starting HTTP server..."
        python albert_server.py --host "${ALBERT_HOST:-127.0.0.1}" --port $ALBERT_HTTP_PORT --no-debug > logs/albert.log 2>&1 &
        ALBERT_PID=$!
        echo $ALBERT_PID > .albert.pid
        log_info "Albert server (dev) started (PID: $ALBERT_PID) -> http://127.0.0.1:$ALBERT_HTTP_PORT"
    fi
}

start_albert_prod() {
    if ! check_risk_gate "${1:-}"; then
        log_error "Refusing to start Albert in PROD without ALBERT_ACCEPT_RISK=1"
        exit 2
    fi
    log_info "Starting Albert server (PROD) with gunicorn on port $ALBERT_HTTP_PORT..."
    pkill -f "gunicorn.*albert_server" 2>/dev/null || true
    pkill -f "albert_server.py.*$ALBERT_HTTP_PORT" 2>/dev/null || true
    # gunicorn binds via gunicorn_conf.py (ALBERT_HOST:ALBERT_HTTP_PORT)
    gunicorn -c gunicorn_conf.py albert_server:app --access-logfile - --error-logfile - > logs/albert.log 2>&1 &
    ALBERT_PID=$!
    echo $ALBERT_PID > .albert.pid
    log_info "Albert (gunicorn) started (PID: $ALBERT_PID) -> http://127.0.0.1:$ALBERT_HTTP_PORT"
    if [[ -f "certs/server.crt" && -f "certs/server.key" ]]; then
        log_info "Note: gunicorn HTTPS not enabled via certs in prod; use reverse proxy for TLS. HTTPS dev mode available via 'dev'."
    fi
}

start_albert() {
    if [[ "$ALBERT_MODE" == "prod" ]]; then
        start_albert_prod "$@"
    else
        if ! check_risk_gate "${1:-}"; then
            log_error "Refusing to start Albert in DEV without ALBERT_ACCEPT_RISK=1 (use --allow-no-risk for lab)"
            exit 2
        fi
        start_albert_dev
    fi
}

start_mitmproxy() {
    log_info "Starting mitmproxy on port $MITMPROXY_PORT (web UI $MITMPROXY_WEB_PORT)..."
    pkill -f "mitmweb.*firmware_restore_proxy" 2>/dev/null || true
    export LOCAL_ALBERT_HOST=127.0.0.1
    export LOCAL_ALBERT_PORT=$ALBERT_HTTP_PORT
    export LOCAL_ALBERT_SCHEME=http
    mitmweb -s firmware_restore_proxy.py --set block_global=false --web-host 127.0.0.1 --web-port $MITMPROXY_WEB_PORT --listen-port $MITMPROXY_PORT > logs/mitmproxy.log 2>&1 &
    MITMPROXY_PID=$!
    echo $MITMPROXY_PID > .mitmproxy.pid
    log_info "mitmproxy started (PID: $MITMPROXY_PID)"
    log_info "Web UI at http://localhost:$MITMPROXY_WEB_PORT  Proxy at localhost:$MITMPROXY_PORT"
}

stop_services() {
    log_info "Stopping services..."
    if [[ -f .albert.pid ]]; then kill $(cat .albert.pid) 2>/dev/null || true; rm -f .albert.pid; fi
    if [[ -f .albert-https.pid ]]; then kill $(cat .albert-https.pid) 2>/dev/null || true; rm -f .albert-https.pid; fi
    if [[ -f .mitmproxy.pid ]]; then kill $(cat .mitmproxy.pid) 2>/dev/null || true; rm -f .mitmproxy.pid; fi
    pkill -f "albert_server.py" 2>/dev/null || true
    pkill -f "gunicorn.*albert_server" 2>/dev/null || true
    pkill -f "mitmweb.*firmware_restore_proxy" 2>/dev/null || true
    log_info "Services stopped"
}

show_status() {
    echo ""
    log_info "=== Service Status ==="
    if [[ -f .albert.pid ]] && kill -0 $(cat .albert.pid) 2>/dev/null; then
        log_info "Albert HTTP: RUNNING (PID: $(cat .albert.pid)) http://127.0.0.1:$ALBERT_HTTP_PORT"
        curl -s http://127.0.0.1:$ALBERT_HTTP_PORT/health 2>&1 | head -n 5 || echo "  Health check failed"
        if [[ -f .albert-https.pid ]] && kill -0 $(cat .albert-https.pid) 2>/dev/null; then
            log_info "Albert HTTPS: RUNNING (PID: $(cat .albert-https.pid)) https://127.0.0.1:$ALBERT_HTTPS_PORT"
            curl -k -s https://127.0.0.1:$ALBERT_HTTPS_PORT/health 2>&1 | head -n 5 || echo "  HTTPS health failed"
        fi
    else
        log_warn "Albert server: STOPPED"
        [[ -f logs/albert.log ]] && tail -n 20 logs/albert.log || [[ -f albert.log ]] && tail -n 20 albert.log
    fi
    if [[ -f .mitmproxy.pid ]] && kill -0 $(cat .mitmproxy.pid) 2>/dev/null; then
        log_info "mitmproxy: RUNNING (PID: $(cat .mitmproxy.pid))"
        log_info "  Web UI: http://localhost:$MITMPROXY_WEB_PORT"
        log_info "  Proxy:  localhost:$MITMPROXY_PORT"
    else
        log_warn "mitmproxy: STOPPED"
        [[ -f logs/mitmproxy.log ]] && tail -n 20 logs/mitmproxy.log || [[ -f mitmproxy.log ]] && tail -n 20 mitmproxy.log
    fi
    echo ""
}

show_device_info() {
    log_info "=== Connected Devices ==="
    if command -v idevice_id &> /dev/null; then
        echo "idevice_id output:"
        idevice_id -l || echo "  No devices (normal mode)"
    else
        log_warn "idevice_id not found. Install libimobiledevice-utils"
    fi
    if command -v irecovery &> /dev/null; then
        echo "irecovery devices:"
        irecovery -a 2>&1 | head -n 20 || echo "  No devices in recovery/DFU"
    fi
    if command -v python3 &> /dev/null && python3 -c "import pymobiledevice3" 2>/dev/null; then
        python3 -c "
try:
    import asyncio
    from pymobiledevice3.usbmux import list_devices
    async def main():
        devices = await list_devices()
        if not devices:
            print('  No pymobiledevice3 devices')
        for d in devices:
            print(f'  UDID: {d.udid}, Name: {getattr(d,\"name\",\"-\")}, Connection: {getattr(d,\"conn_type\",\"-\")}')
    asyncio.run(main())
except Exception as e:
    print(f'  pymobiledevice3 error: {e}')
" 2>&1 || true
    fi
    echo ""
}

# Ensure trap for graceful shutdown on INT/TERM
trap stop_services INT TERM

case "${1:-start}" in
    start)
        # default start respects ALBERT_MODE (prod=gunicorn, dev=python)
        stop_services
        start_albert
        sleep 3
        start_mitmproxy
        sleep 3
        show_status
        show_device_info
        log_info "Services started (mode=$ALBERT_MODE). Press Ctrl+C to stop."
        log_info "Albert: http://127.0.0.1:$ALBERT_HTTP_PORT/health  mitmproxy: http://localhost:$MITMPROXY_WEB_PORT"
        trap stop_services INT TERM
        wait
        ;;
    prod)
        ALBERT_MODE=prod
        stop_services
        start_albert_prod
        sleep 3
        start_mitmproxy
        sleep 3
        show_status
        log_info "Services started in PROD (gunicorn). Press Ctrl+C to stop."
        trap stop_services INT TERM
        wait
        ;;
    dev)
        ALBERT_MODE=dev
        stop_services
        start_albert_dev
        sleep 3
        start_mitmproxy
        sleep 3
        show_status
        log_info "Services started in DEV (python). Press Ctrl+C to stop."
        trap stop_services INT TERM
        wait
        ;;
    stop)
        stop_services
        ;;
    restart)
        stop_services
        sleep 1
        $0 start
        ;;
    status)
        show_status
        show_device_info
        ;;
    logs)
        echo "=== albert.log ==="
        tail -n 50 logs/albert.log 2>&1 || tail -n 50 albert.log 2>&1 || echo "no log"
        echo "=== mitmproxy.log ==="
        tail -n 50 logs/mitmproxy.log 2>&1 || tail -n 50 mitmproxy.log 2>&1 || echo "no log"
        ;;
    activate)
        shift
        python activate_device.py --albert-url http://127.0.0.1:$ALBERT_HTTP_PORT "$@"
        ;;
    docker-up)
        log_info "Starting with Docker..."
        docker compose up -d
        log_info "Services started. Albert: http://localhost:$ALBERT_HTTP_PORT, mitmproxy UI: http://localhost:$MITMPROXY_WEB_PORT"
        ;;
    docker-down)
        docker compose down
        ;;
    docker-logs)
        docker compose logs -f
        ;;
    *)
        echo "Usage: $0 {start|prod|dev|stop|restart|status|logs|activate|docker-up|docker-down|docker-logs}"
        echo ""
        echo "Ports: Albert HTTP $ALBERT_HTTP_PORT (default 18090), HTTPS $ALBERT_HTTPS_PORT, mitmproxy $MITMPROXY_PORT web $MITMPROXY_WEB_PORT"
        echo "Modes: ALBERT_MODE=prod (gunicorn, default) or dev (python)"
        exit 1
        ;;
esac
