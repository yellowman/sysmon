Sysmon Web Configuration Manager

A modern web interface for managing sysmon network monitoring configurations.

Features

  - Real-time Dashboard: Live monitoring status with auto-refresh
  - Host Management: View all monitored hosts and their check results
  - SNMP Trap Viewer: Decoded SNMP traps with detailed information
  - Configuration Editor: Edit sysmon.conf with version control
  - Backup & Restore: Automatic backups with restore functionality
  - Audit Logging: Track all configuration changes
  - FastCGI Support: Production-ready FastCGI deployment

Architecture

  - Backend: Pure Go with standard library only
  - Frontend: HTML templates with Alpine.js and Tailwind CSS
  - API: RESTful JSON API for monitoring data
  - Config Management: File-based with optimistic locking (SHA256 versioning)
  - Monitoring: Direct XML output from sysmon daemon via MODE xml

Prerequisites

  - Go 1.21 or later
  - Running sysmon daemon
  - Web server with FastCGI support (nginx, Apache) for production

Building

`bash
cd web-ui
make build
`

Development Mode

Run with built-in HTTP server:

`bash
make dev
`

Then open http://localhost:8080 in your browser.

Or manually:

`bash
cd backend
go run ./cmd/sysmon-web \
  - listen :8080 \
  - templates ./templates \
  - config /etc/sysmon.conf \
  - sysmon localhost:3333 \
  - backups /var/backups/sysmon \
  - audit /var/log/sysmon-web-audit.log
`

Installation

`bash
make install
`

This installs:
  - Binary: /usr/local/bin/sysmon-web
  - Templates: /usr/local/libexec/sysmon-web/templates/
  - Static files: /usr/local/libexec/sysmon-web/static/

Production Deployment (FastCGI + Nginx)

1. Create systemd service

/etc/systemd/system/sysmon-web.service:

`ini
[Unit]
Description=Sysmon Web Configuration Manager
After=network.target sysmond.service

[Service]
Type=simple
User=www-data
Group=www-data
ExecStart=/usr/local/bin/sysmon-web \
  - socket /var/run/sysmon-web.sock \
  - config /etc/sysmon.conf \
  - sysmon localhost:3333 \
  - templates /usr/local/libexec/sysmon-web/templates \
  - backups /var/backups/sysmon \
  - audit /var/log/sysmon-web-audit.log
Restart=always

[Install]
WantedBy=multi-user.target
`

2. Configure Nginx

`nginx
server {
    listen 80;
    server_name sysmon.example.com;

    location / {
        include fastcgi_params;
        fastcgi_pass unix:/var/run/sysmon-web.sock;
    }

    location /static/ {
        alias /usr/local/libexec/sysmon-web/static/;
        expires 1h;
    }
}
`

3. Start service

`bash
sudo systemctl enable sysmon-web
sudo systemctl start sysmon-web
sudo systemctl reload nginx
`

API Endpoints

Configuration Management

  - GET /api/config - Get config snapshot with version
  - PUT /api/config - Update config (with optimistic locking)
  - GET /api/config/raw - Get raw sysmon.conf
  - PUT /api/config/raw - Update raw config
  - POST /api/config/validate - Validate config without saving
  - POST /api/config/reload - Reload sysmon (SIGHUP)

Hosts

  - GET /api/hosts - List all configured hosts
  - GET /api/hosts/:id - Get specific host configuration

Contacts

  - GET /api/contacts - List all contacts

Backups

  - GET /api/backups - List available backups
  - POST /api/backups/:filename/restore - Restore a backup

Live Monitoring (from sysmon daemon)

  - GET /api/monitoring/status - Complete sysmon status (JSON)
  - GET /api/monitoring/hosts - All hosts status
  - GET /api/monitoring/host/:name - Specific host status
  - GET /api/monitoring/alerts - Active alerts (WARNING/CRITICAL)
  - GET /api/monitoring/traps - Recent SNMP traps
  - GET /api/monitoring/traps/:source - Traps from specific source
  - GET /api/monitoring/stats - Statistics summary

Configuration

Command-line flags:

  - -socket - FastCGI socket path (default: /var/run/sysmon-web.sock)
  - -listen - HTTP listen address for dev mode (empty = FastCGI mode)
  - -config - Sysmon config file path (default: /etc/sysmon.conf)
  - -sysmon - Sysmon daemon address (default: localhost:3333)
  - -templates - Templates directory (default: ./templates)
  - -backups - Backup directory (default: /var/backups/sysmon)
  - -audit - Audit log file (default: /var/log/sysmon-web-audit.log)

Security Considerations

1. Authentication: This version has no built-in authentication. Use reverse proxy authentication (nginx auth_basic, oauth2_proxy, etc.)

2. Authorization: The web UI can modify the sysmon configuration. Restrict access appropriately.

3. Firewall: Block direct access to sysmon client port (3333) from untrusted networks.

4. HTTPS: Use HTTPS in production via nginx/Apache.

5. File Permissions:
   `bash
   chown www-data:www-data /etc/sysmon.conf
   chmod 644 /etc/sysmon.conf
   mkdir -p /var/backups/sysmon
   chown www-data:www-data /var/backups/sysmon
   chmod 755 /var/backups/sysmon
   `

Optimistic Locking

The web UI uses SHA256 hash-based versioning to prevent concurrent edit conflicts:

1. Client fetches config with version hash
2. User modifies config
3. Client submits update with original version hash
4. Server verifies hash matches current file
5. If mismatch: return 409 Conflict with current config
6. If match: save changes and return new version

Backups

Automatic backups are created on every config change:
  - Filename format: sysmon-YYYYMMDD-HHMMSS.conf
  - Stored in backup directory
  - Can be restored via web UI

Audit Log

All configuration changes are logged with:
  - Timestamp
  - Action (config_update, restore_backup, etc.)
  - User (from X-User header if available)
  - IP address
  - Details/comment

Sysmon Protocol

The web UI communicates with sysmon daemon using the XML mode protocol. After connecting to the daemon's client port, it sends MODE xml to enable structured XML output, then uses commands like STATO, SHOWOBJ, and UPD to retrieve monitoring data.

Browser Compatibility

  - Modern browsers with ES6 support
  - Alpine.js for reactivity
  - Tailwind CSS (CDN) for styling
  - Chart.js for visualizations

Troubleshooting

Cannot connect to sysmon daemon

`bash
Check sysmon is running
ps aux | grep sysmond

Check client port is listening
netstat -ln | grep 3333

Test connection manually
telnet localhost 3333
json
`

Configuration changes not taking effect

`bash
Check sysmon PID file exists
cat /var/run/sysmond.pid

Check sysmon received SIGHUP
journalctl -u sysmond -n 50

Manually reload
kill -HUP $(cat /var/run/sysmond.pid)
`

Permission denied errors

`bash
Ensure www-data can write to config
ls -l /etc/sysmon.conf

Ensure backup directory is writable
ls -ld /var/backups/sysmon

Check service user
systemctl status sysmon-web
`

Development

Project structure:

`
web-ui/
+-- backend/
|   +-- cmd/sysmon-web/     # Main application
|   +-- internal/
|   |   +-- api/            # HTTP handlers & routing
|   |   +-- config/         # Config service (parse/generate)
|   |   +-- monitoring/     # Monitoring service (sysmon connection)
|   |   +-- models/         # Data models
|   +-- templates/          # HTML templates
|   +-- static/             # Static assets (future)
|   +-- go.mod
+-- Makefile
+-- README.md
`

Run tests:

`bash
make test
`

Format code:

`bash
make fmt
`

License

Same as sysmon (check main repository LICENSE file)

Contributing

1. Test thoroughly with real sysmon daemon
2. Follow Go best practices
3. Maintain backward compatibility with sysmon.conf format
4. Update documentation

Author

Generated by Claude Code for the sysmon project.
