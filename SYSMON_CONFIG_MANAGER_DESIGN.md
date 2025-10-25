# Sysmon Config Manager - Design Document

## Overview

A modern web-based configuration management system for sysmon, built with Go backend and React frontend, deployed via FastCGI for seamless integration with existing web servers.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Web Browser                            │
│  ┌──────────────────────────────────────────────────────┐  │
│  │         React Frontend (Tailwind CSS)                │  │
│  │  - Dashboard  - Hosts  - Checks  - Alerts           │  │
│  └──────────────────────────────────────────────────────┘  │
└───────────────────────┬─────────────────────────────────────┘
                        │ HTTPS/REST API
                        ▼
┌─────────────────────────────────────────────────────────────┐
│                 Nginx/Apache (Reverse Proxy)                │
│                    ┌──────────────┐                         │
│                    │  FastCGI     │                         │
│                    │  Socket      │                         │
│                    └──────┬───────┘                         │
└───────────────────────────┼─────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│              Go Application (sysmon-webui)                  │
│  ┌────────────────────────────────────────────────────┐    │
│  │              HTTP/FastCGI Server                   │    │
│  ├────────────────────────────────────────────────────┤    │
│  │  REST API Handlers                                 │    │
│  │  - /api/hosts      - /api/checks                   │    │
│  │  - /api/contacts   - /api/services                 │    │
│  │  - /api/config     - /api/reload                   │    │
│  ├────────────────────────────────────────────────────┤    │
│  │  Config Parser/Generator                           │    │
│  │  - Parse sysmon.conf (lex/yacc based)              │    │
│  │  - Generate sysmon.conf (templating)               │    │
│  │  - Validation (syntax, semantics)                  │    │
│  ├────────────────────────────────────────────────────┤    │
│  │  Business Logic                                    │    │
│  │  - CRUD operations for all config entities        │    │
│  │  - Config diff/history                             │    │
│  │  - Validation rules                                │    │
│  ├────────────────────────────────────────────────────┤    │
│  │  Sysmon Integration                                │    │
│  │  - Config reload (SIGHUP)                          │    │
│  │  - Status monitoring (via sysmon client)           │    │
│  │  - Log tailing                                     │    │
│  └────────────────────────────────────────────────────┘    │
└─────────────────┬────────────────────────┬──────────────────┘
                  │
                  ▼
    ┌──────────────────────────────────────┐
    │  /etc/sysmon.conf                    │
    │  (single source of truth)            │
    │                                      │
    │  /etc/sysmon.conf.backup.TIMESTAMP   │
    │  (automatic backups on every change) │
    │                                      │
    │  /var/log/sysmon-webui/audit.log     │
    │  (change audit trail)                │
    └──────────────────────────────────────┘
                  │
                  ▼
    ┌──────────────────────────────────────┐
    │        sysmond daemon                │
    │  (receives SIGHUP to reload config)  │
    └──────────────────────────────────────┘
```

## Technology Stack

### Backend (Go)
- **Framework**: `net/http` + `net/http/fcgi` for FastCGI
- **Router**: `chi` - lightweight, idiomatic router
- **Config Parser**: Custom parser (reuse sysmon's parser.l concepts) or `goparsify`
- **Storage**: File-based only - read/write `/etc/sysmon.conf` directly
- **Validation**: `go-playground/validator/v10`
- **Logging**: `zerolog`
- **Process Control**: `os/signal` for SIGHUP to sysmond
- **File Locking**: `syscall.Flock` for safe concurrent access

### Frontend (React)
- **Framework**: React 18 with TypeScript
- **Styling**: Tailwind CSS 3
- **UI Components**:
  - `shadcn/ui` (Radix UI primitives + Tailwind)
  - `lucide-react` for icons
- **State Management**:
  - `TanStack Query` (React Query) for server state
  - `zustand` for client state
- **Forms**: `react-hook-form` + `zod` validation
- **Routing**: `react-router-dom`
- **HTTP Client**: `axios` with interceptors
- **Build**: Vite

### DevOps
- **Deployment**: Systemd service + FastCGI socket
- **Web Server**: Nginx (FastCGI proxy)
- **Build**: Makefile + `go build`
- **Assets**: Embedded via `embed` package (Go 1.16+)

## Data Models

### Core Entities

```go
// Host represents a monitored host/device
type Host struct {
    ID                string    `json:"id" db:"id"`
    Hostname          string    `json:"hostname" validate:"required,fqdn|ipv4"`
    Description       string    `json:"description"`
    Contact           string    `json:"contact" validate:"required"`
    MaxWakeupRetries  int       `json:"max_wakeup_retries"`
    TrapAlert         bool      `json:"trap_alert"`
    Checks            []Check   `json:"checks"`
    CreatedAt         time.Time `json:"created_at"`
    UpdatedAt         time.Time `json:"updated_at"`
}

// Check represents a monitoring check
type Check struct {
    ID              string            `json:"id" db:"id"`
    HostID          string            `json:"host_id" db:"host_id"`
    Type            CheckType         `json:"type" validate:"required"`
    Interval        int               `json:"interval" validate:"required,min=1"`
    Timeout         int               `json:"timeout" validate:"required,min=1"`
    Params          map[string]any    `json:"params"`
    Enabled         bool              `json:"enabled"`
    CreatedAt       time.Time         `json:"created_at"`
    UpdatedAt       time.Time         `json:"updated_at"`
}

type CheckType string

const (
    CheckPing       CheckType = "ping"
    CheckTCP        CheckType = "tcp"
    CheckHTTP       CheckType = "http"
    CheckHTTPS      CheckType = "https"
    CheckSMTP       CheckType = "smtp"
    CheckPOP3       CheckType = "pop3"
    CheckIMAP       CheckType = "imap"
    CheckSSH        CheckType = "ssh"
    CheckDNS        CheckType = "dns"
    CheckSNMP       CheckType = "snmp"
    CheckRTT        CheckType = "rtt"
)

// Contact represents an alert contact
type Contact struct {
    ID          string    `json:"id" db:"id"`
    Name        string    `json:"name" validate:"required"`
    Email       string    `json:"email" validate:"required,email"`
    Phone       string    `json:"phone"`
    Pager       string    `json:"pager"`
    Method      string    `json:"method" validate:"required,oneof=email sms page"`
    Enabled     bool      `json:"enabled"`
    CreatedAt   time.Time `json:"created_at"`
    UpdatedAt   time.Time `json:"updated_at"`
}

// GlobalConfig represents global sysmon settings
type GlobalConfig struct {
    LogFacility      string `json:"log_facility"`
    StatusInterval   int    `json:"status_interval"`
    KillAfter        int    `json:"kill_after"`
    WarnAfter        int    `json:"warn_after"`
    MaxCheckInterval int    `json:"max_check_interval"`
    DisableICMP      bool   `json:"disable_icmp"`
    SNMPTrapPort     int    `json:"snmp_trap_port"`
}

// ConfigSnapshot represents the current config state with version
type ConfigSnapshot struct {
    Version     string       `json:"version"`      // SHA256 hash of content
    ModifiedAt  time.Time    `json:"modified_at"`  // File mtime
    Global      GlobalConfig `json:"global"`
    Hosts       []Host       `json:"hosts"`
    Contacts    []Contact    `json:"contacts"`
}

// ConfigUpdate represents a config update request with optimistic locking
type ConfigUpdate struct {
    Version     string       `json:"version" validate:"required"` // Must match current version
    Comment     string       `json:"comment"`                     // Optional change description
    Global      GlobalConfig `json:"global"`
    Hosts       []Host       `json:"hosts"`
    Contacts    []Contact    `json:"contacts"`
}

// VersionConflict represents a version mismatch error
type VersionConflict struct {
    ExpectedVersion string          `json:"expected_version"`
    ActualVersion   string          `json:"actual_version"`
    CurrentConfig   *ConfigSnapshot `json:"current_config"`
    Message         string          `json:"message"`
}
```

## REST API Design

### Authentication
```
POST   /api/auth/login
POST   /api/auth/logout
GET    /api/auth/me
```

### Hosts
```
GET    /api/hosts                    # List all hosts
GET    /api/hosts/:id                # Get single host
POST   /api/hosts                    # Create host
PUT    /api/hosts/:id                # Update host
DELETE /api/hosts/:id                # Delete host
GET    /api/hosts/:id/checks         # Get host's checks
GET    /api/hosts/:id/status         # Get live status from sysmon
```

### Checks
```
GET    /api/checks                   # List all checks
GET    /api/checks/:id               # Get single check
POST   /api/checks                   # Create check
PUT    /api/checks/:id               # Update check
DELETE /api/checks/:id               # Delete check
POST   /api/checks/:id/test          # Test check manually
```

### Contacts
```
GET    /api/contacts                 # List all contacts
GET    /api/contacts/:id             # Get single contact
POST   /api/contacts                 # Create contact
PUT    /api/contacts/:id             # Update contact
DELETE /api/contacts/:id             # Delete contact
POST   /api/contacts/:id/test        # Send test alert
```

### Configuration
```
GET    /api/config                   # Get config snapshot with version
PUT    /api/config                   # Update config (with version check)
POST   /api/config/validate          # Validate config without saving
POST   /api/config/reload            # Reload sysmon (SIGHUP)
GET    /api/config/raw               # Get raw sysmon.conf with version
PUT    /api/config/raw               # Update raw config (with version check)
```

**Optimistic Locking Flow:**
```
1. GET /api/config -> Returns { version: "abc123", ... }
2. User edits config in UI
3. PUT /api/config with { version: "abc123", ... }
4. Server checks if version matches current file
   - Match: Apply changes, return new version
   - Mismatch: Return 409 Conflict with current config
```

### Config Backups
```
GET    /api/backups                  # List backup files
GET    /api/backups/:timestamp       # Get specific backup
POST   /api/backups/:timestamp/restore  # Restore from backup
```

### Live Monitoring (Query Sysmon Daemon via JSON)
```
GET    /api/monitoring/status        # Get complete sysmon status (JSON from daemon)
GET    /api/monitoring/hosts         # Get all hosts status
GET    /api/monitoring/host/:name    # Get specific host status with all checks
GET    /api/monitoring/alerts        # Get active alerts
GET    /api/monitoring/traps         # Get recent SNMP traps
GET    /api/monitoring/traps/:source # Get traps from specific source
GET    /api/monitoring/stats         # Get statistics (uptime, check counts, etc)
```

**Note:** These endpoints query the live sysmon daemon via JSON output mode, NOT the config file.

### Audit
```
GET    /api/audit                    # Get recent audit log entries (from file)
```

## Config Parser/Generator

### Parser Strategy

```go
package parser

// Parser reads sysmon.conf and converts to internal models
type Parser struct {
    lexer *Lexer
}

// Parse parses the config file
func (p *Parser) Parse(filename string) (*Config, error) {
    // Read file
    // Tokenize (similar to parser.l logic)
    // Build AST
    // Convert to internal models
    // Validate
    return config, nil
}

// Config represents the entire parsed configuration
type Config struct {
    Global   GlobalConfig
    Hosts    []Host
    Contacts []Contact
}
```

### Generator Strategy

```go
package generator

// Generator writes internal models to sysmon.conf format
type Generator struct {
    template *template.Template
}

// Generate creates sysmon.conf from internal models
func (g *Generator) Generate(config *Config) (string, error) {
    // Use text/template with sysmon.conf template
    // Generate hosts, contacts, checks
    // Format consistently
    return configText, nil
}
```

### Template Example

```go
const configTemplate = `
# Sysmon Configuration
# Generated by sysmon-webui on {{ .Timestamp }}

{{ if .Global.LogFacility }}
log_facility {{ .Global.LogFacility }}
{{ end }}

{{ if .Global.SNMPTrapPort }}
snmp_trap_port {{ .Global.SNMPTrapPort }}
{{ end }}

{{ range .Contacts }}
contact {{ .Name }} {
    email {{ .Email }}
    {{ if .Phone }}phone {{ .Phone }}{{ end }}
    {{ if .Pager }}pager {{ .Pager }}{{ end }}
}
{{ end }}

{{ range .Hosts }}
host {{ .Hostname }} {
    contact {{ .Contact }}
    {{ if .Description }}description "{{ .Description }}"{{ end }}
    {{ if .MaxWakeupRetries }}max_wakeup_retries {{ .MaxWakeupRetries }}{{ end }}
    {{ if .TrapAlert }}trap_alert{{ end }}

    {{ range .Checks }}
    {{ .Type }} {
        interval {{ .Interval }}
        timeout {{ .Timeout }}
        {{ range $key, $value := .Params }}
        {{ $key }} {{ $value }}
        {{ end }}
    }
    {{ end }}
}
{{ end }}
`
```

## Frontend Architecture

### Component Structure

```
src/
├── components/
│   ├── layout/
│   │   ├── Sidebar.tsx
│   │   ├── Header.tsx
│   │   └── Layout.tsx
│   ├── hosts/
│   │   ├── HostList.tsx
│   │   ├── HostCard.tsx
│   │   ├── HostForm.tsx
│   │   └── HostDetails.tsx
│   ├── checks/
│   │   ├── CheckList.tsx
│   │   ├── CheckForm.tsx
│   │   ├── CheckTypeSelector.tsx
│   │   └── CheckStatus.tsx
│   ├── contacts/
│   │   ├── ContactList.tsx
│   │   ├── ContactForm.tsx
│   │   └── ContactCard.tsx
│   ├── config/
│   │   ├── GlobalConfig.tsx
│   │   ├── ConfigEditor.tsx (Monaco editor for raw config)
│   │   └── ConfigDiff.tsx
│   ├── dashboard/
│   │   ├── Dashboard.tsx
│   │   ├── StatusOverview.tsx
│   │   ├── AlertsWidget.tsx
│   │   └── HealthChart.tsx
│   └── common/
│       ├── Button.tsx
│       ├── Input.tsx
│       ├── Select.tsx
│       ├── Modal.tsx
│       ├── Table.tsx
│       └── Toast.tsx
├── pages/
│   ├── DashboardPage.tsx
│   ├── HostsPage.tsx
│   ├── ChecksPage.tsx
│   ├── ContactsPage.tsx
│   ├── ConfigPage.tsx
│   └── AuditPage.tsx
├── hooks/
│   ├── useHosts.ts
│   ├── useChecks.ts
│   ├── useContacts.ts
│   └── useConfig.ts
├── services/
│   └── api.ts
├── types/
│   └── index.ts
└── App.tsx
```

### Key React Components

#### Dashboard
```tsx
// Dashboard with status overview
export function Dashboard() {
  const { data: status } = useQuery(['status'], api.getStatus)
  const { data: alerts } = useQuery(['alerts'], api.getAlerts)

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
      <StatusCard title="Total Hosts" value={status.totalHosts} />
      <StatusCard title="Active Checks" value={status.activeChecks} />
      <StatusCard title="Alerts" value={alerts.length} color="red" />
      <StatusCard title="Uptime" value={status.uptime} />

      <div className="col-span-full">
        <HostHealthChart data={status.hosts} />
      </div>

      <div className="col-span-full lg:col-span-2">
        <RecentAlerts alerts={alerts} />
      </div>

      <div className="col-span-full lg:col-span-2">
        <RecentChanges />
      </div>
    </div>
  )
}
```

#### Host Management
```tsx
// Host list with add/edit/delete
export function HostList() {
  const { data: hosts, isLoading } = useHosts()
  const deleteMutation = useMutation(api.deleteHost)
  const [showForm, setShowForm] = useState(false)
  const [editHost, setEditHost] = useState(null)

  return (
    <div className="space-y-4">
      <div className="flex justify-between items-center">
        <h1 className="text-2xl font-bold">Monitored Hosts</h1>
        <Button onClick={() => setShowForm(true)}>
          <Plus className="mr-2" /> Add Host
        </Button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {hosts?.map(host => (
          <HostCard
            key={host.id}
            host={host}
            onEdit={() => { setEditHost(host); setShowForm(true) }}
            onDelete={() => deleteMutation.mutate(host.id)}
          />
        ))}
      </div>

      {showForm && (
        <Modal onClose={() => setShowForm(false)}>
          <HostForm
            host={editHost}
            onSuccess={() => setShowForm(false)}
          />
        </Modal>
      )}
    </div>
  )
}
```

#### Check Configuration
```tsx
// Check form with type-specific fields
export function CheckForm({ hostId, check, onSuccess }) {
  const { register, handleSubmit, watch } = useForm()
  const checkType = watch('type')
  const mutation = useMutation(
    check ? api.updateCheck : api.createCheck
  )

  const onSubmit = (data) => {
    mutation.mutate(data, { onSuccess })
  }

  return (
    <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
      <Select
        label="Check Type"
        {...register('type', { required: true })}
      >
        <option value="ping">ICMP Ping</option>
        <option value="tcp">TCP Port</option>
        <option value="http">HTTP</option>
        <option value="https">HTTPS</option>
        <option value="smtp">SMTP</option>
        <option value="dns">DNS</option>
        <option value="snmp">SNMP</option>
        <option value="rtt">RTT/Jitter</option>
      </Select>

      <Input
        label="Interval (seconds)"
        type="number"
        {...register('interval', { required: true, min: 1 })}
      />

      <Input
        label="Timeout (seconds)"
        type="number"
        {...register('timeout', { required: true, min: 1 })}
      />

      {/* Type-specific fields */}
      {checkType === 'tcp' && (
        <Input
          label="Port"
          type="number"
          {...register('params.port', { required: true })}
        />
      )}

      {checkType === 'http' || checkType === 'https' ? (
        <>
          <Input
            label="URL Path"
            {...register('params.path')}
          />
          <Input
            label="Expected Status"
            type="number"
            {...register('params.status')}
          />
        </>
      ) : null}

      {checkType === 'snmp' && (
        <>
          <Input
            label="OID"
            {...register('params.oid', { required: true })}
          />
          <Input
            label="Community"
            {...register('params.community')}
            defaultValue="public"
          />
        </>
      )}

      {checkType === 'rtt' && (
        <>
          <Input
            label="RTT Threshold (ms)"
            type="number"
            {...register('params.rtt_threshold')}
          />
          <Input
            label="Jitter Threshold (ms)"
            type="number"
            {...register('params.jitter_threshold')}
          />
          <Input
            label="Samples"
            type="number"
            {...register('params.samples')}
            defaultValue="10"
          />
        </>
      )}

      <div className="flex gap-2">
        <Button type="submit" disabled={mutation.isLoading}>
          {check ? 'Update' : 'Create'} Check
        </Button>
        <Button variant="outline" onClick={onSuccess}>
          Cancel
        </Button>
      </div>
    </form>
  )
}
```

#### Config Editor (Raw Mode)
```tsx
// Raw config editor with Monaco
import Editor from '@monaco-editor/react'

export function ConfigEditor() {
  const { data: config } = useQuery(['config', 'raw'], api.getRawConfig)
  const [value, setValue] = useState(config)
  const mutation = useMutation(api.updateRawConfig)
  const validateMutation = useMutation(api.validateConfig)

  const handleValidate = async () => {
    const result = await validateMutation.mutateAsync(value)
    if (result.valid) {
      toast.success('Configuration is valid')
    } else {
      toast.error(`Validation errors: ${result.errors.join(', ')}`)
    }
  }

  const handleSave = () => {
    mutation.mutate(value, {
      onSuccess: () => toast.success('Configuration saved'),
      onError: (err) => toast.error(err.message)
    })
  }

  return (
    <div className="h-screen flex flex-col">
      <div className="flex justify-between p-4 bg-gray-100">
        <h2 className="text-xl font-bold">Raw Configuration</h2>
        <div className="flex gap-2">
          <Button onClick={handleValidate}>
            Validate
          </Button>
          <Button onClick={handleSave}>
            Save & Reload
          </Button>
        </div>
      </div>

      <Editor
        height="90%"
        defaultLanguage="shell"
        value={value}
        onChange={setValue}
        theme="vs-dark"
        options={{
          minimap: { enabled: false },
          fontSize: 14,
        }}
      />
    </div>
  )
}
```

## Backend Implementation Details

### Main Application Structure

```go
package main

import (
    "net/http"
    "net/http/fcgi"
    "github.com/go-chi/chi/v5"
    "github.com/go-chi/chi/v5/middleware"
)

func main() {
    r := chi.NewRouter()

    // Middleware
    r.Use(middleware.Logger)
    r.Use(middleware.Recoverer)
    r.Use(middleware.RequestID)
    r.Use(CORSMiddleware)

    // API routes
    r.Route("/api", func(r chi.Router) {
        r.Route("/hosts", func(r chi.Router) {
            r.Get("/", listHosts)
            r.Post("/", createHost)
            r.Get("/{id}", getHost)
            r.Put("/{id}", updateHost)
            r.Delete("/{id}", deleteHost)
            r.Get("/{id}/status", getHostStatus)
        })

        r.Route("/checks", func(r chi.Router) {
            r.Get("/", listChecks)
            r.Post("/", createCheck)
            r.Get("/{id}", getCheck)
            r.Put("/{id}", updateCheck)
            r.Delete("/{id}", deleteCheck)
            r.Post("/{id}/test", testCheck)
        })

        r.Route("/contacts", func(r chi.Router) {
            r.Get("/", listContacts)
            r.Post("/", createContact)
            r.Get("/{id}", getContact)
            r.Put("/{id}", updateContact)
            r.Delete("/{id}", deleteContact)
        })

        r.Route("/config", func(r chi.Router) {
            r.Get("/", getGlobalConfig)
            r.Put("/", updateGlobalConfig)
            r.Post("/validate", validateConfig)
            r.Post("/reload", reloadSysmon)
            r.Get("/raw", getRawConfig)
            r.Put("/raw", updateRawConfig)
        })

        r.Get("/status", getStatus)
        r.Get("/versions", listVersions)
        r.Get("/audit", listAuditLog)
    })

    // Serve embedded frontend
    r.Get("/*", serveSPA)

    // Start FastCGI server
    listener, err := net.Listen("unix", "/var/run/sysmon-webui.sock")
    if err != nil {
        log.Fatal(err)
    }
    defer listener.Close()

    log.Println("FastCGI server listening on /var/run/sysmon-webui.sock")
    fcgi.Serve(listener, r)
}
```

### Config Service (Core Logic)

```go
package service

import (
    "crypto/sha256"
    "encoding/hex"
    "fmt"
    "os"
    "syscall"
)

type ConfigService struct {
    parser    *parser.Parser
    generator *generator.Generator
    confPath  string
    mu        sync.RWMutex  // Protects file access
}

// GetConfig reads config and returns snapshot with version
func (s *ConfigService) GetConfig() (*ConfigSnapshot, error) {
    s.mu.RLock()
    defer s.mu.RUnlock()

    // Read file
    content, err := os.ReadFile(s.confPath)
    if err != nil {
        return nil, fmt.Errorf("read failed: %w", err)
    }

    // Get file modification time
    fileInfo, err := os.Stat(s.confPath)
    if err != nil {
        return nil, fmt.Errorf("stat failed: %w", err)
    }

    // Parse config
    config, err := s.parser.Parse(string(content))
    if err != nil {
        return nil, fmt.Errorf("parse failed: %w", err)
    }

    // Calculate version (SHA256 hash of content)
    hash := sha256.Sum256(content)
    version := hex.EncodeToString(hash[:])

    return &ConfigSnapshot{
        Version:    version,
        ModifiedAt: fileInfo.ModTime(),
        Global:     config.Global,
        Hosts:      config.Hosts,
        Contacts:   config.Contacts,
    }, nil
}

// UpdateConfig updates config with optimistic locking
func (s *ConfigService) UpdateConfig(update *ConfigUpdate, user string, ip string) (*ConfigSnapshot, error) {
    s.mu.Lock()
    defer s.mu.Unlock()

    // 1. Get current version
    current, err := s.getCurrentVersion()
    if err != nil {
        return nil, fmt.Errorf("get current version failed: %w", err)
    }

    // 2. Check version match (optimistic locking)
    if update.Version != current {
        // Version conflict - someone else modified the config
        currentSnapshot, err := s.GetConfig()
        if err != nil {
            // Cannot read current config for conflict resolution
            return nil, fmt.Errorf("version conflict detected but unable to read current config: %w", err)
        }
        return nil, &VersionConflictError{
            Expected: update.Version,
            Actual:   current,
            Current:  currentSnapshot,
            Message:  "Config was modified by another user. Please review changes and try again.",
        }
    }

    // 3. Validate config
    config := &Config{
        Global:   update.Global,
        Hosts:    update.Hosts,
        Contacts: update.Contacts,
    }
    if err := s.validateConfig(config); err != nil {
        return nil, fmt.Errorf("validation failed: %w", err)
    }

    // 4. Generate config text
    configText, err := s.generator.Generate(config)
    if err != nil {
        return nil, fmt.Errorf("generation failed: %w", err)
    }

    // 5. Backup current config (timestamped)
    if err := s.backupConfig(); err != nil {
        return nil, fmt.Errorf("backup failed: %w", err)
    }

    // 6. Write new config atomically
    if err := s.writeConfigAtomic(configText); err != nil {
        return nil, fmt.Errorf("write failed: %w", err)
    }

    // 7. Log change to audit log
    s.logAudit("config_update", user, ip, update.Comment)

    // 8. Return new snapshot
    return s.GetConfig()
}

// getCurrentVersion gets the current config version without parsing
func (s *ConfigService) getCurrentVersion() (string, error) {
    content, err := os.ReadFile(s.confPath)
    if err != nil {
        return "", err
    }
    hash := sha256.Sum256(content)
    return hex.EncodeToString(hash[:]), nil
}

// ReloadSysmon sends SIGHUP to sysmon daemon
func (s *ConfigService) ReloadSysmon() error {
    // Read PID from file
    pidBytes, err := os.ReadFile("/var/run/sysmond.pid")
    if err != nil {
        return fmt.Errorf("read PID failed: %w", err)
    }

    pid, err := strconv.Atoi(strings.TrimSpace(string(pidBytes)))
    if err != nil {
        return fmt.Errorf("parse PID failed: %w", err)
    }

    // Find process
    process, err := os.FindProcess(pid)
    if err != nil {
        return fmt.Errorf("find process failed: %w", err)
    }

    // Send SIGHUP
    if err := process.Signal(syscall.SIGHUP); err != nil {
        return fmt.Errorf("signal failed: %w", err)
    }

    // Log reload
    log.Printf("Sent SIGHUP to sysmond (PID %d)", pid)

    return nil
}

// writeConfigAtomic writes config atomically using temp file + rename
func (s *ConfigService) writeConfigAtomic(content string) error {
    tmpFile := s.confPath + ".tmp"

    // Write to temp file
    if err := os.WriteFile(tmpFile, []byte(content), 0644); err != nil {
        return err
    }

    // Atomic rename
    if err := os.Rename(tmpFile, s.confPath); err != nil {
        os.Remove(tmpFile) // Clean up temp file
        return err
    }

    return nil
}

// backupConfig creates timestamped backup
func (s *ConfigService) backupConfig() error {
    timestamp := time.Now().Format("20060102-150405")
    backupPath := fmt.Sprintf("%s.backup.%s", s.confPath, timestamp)

    input, err := os.ReadFile(s.confPath)
    if err != nil {
        return err
    }

    return os.WriteFile(backupPath, input, 0644)
}

// logAudit appends to audit log file
func (s *ConfigService) logAudit(action, user, ip, comment string) {
    logFile := "/var/log/sysmon-webui/audit.log"
    timestamp := time.Now().Format(time.RFC3339)

    entry := fmt.Sprintf("%s | %s | %s | %s | %s\n",
        timestamp, action, user, ip, comment)

    f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
    if err != nil {
        log.Printf("Failed to write audit log: %v", err)
        return
    }
    defer f.Close()

    f.WriteString(entry)
}
```

### Live Monitoring Service (JSON from Sysmon Daemon)

The web UI connects to the sysmon daemon and requests JSON output, eliminating fragile text parsing.

```go
package service

import (
    "bufio"
    "fmt"
    "net"
    "regexp"
    "strings"
    "time"
)

type StatusService struct {
    sysmonHost string  // default: "localhost:3355"
}

// Status represents the pretty-formatted sysmon status
type Status struct {
    Uptime        string        `json:"uptime"`
    TotalHosts    int           `json:"total_hosts"`
    HealthyHosts  int           `json:"healthy_hosts"`
    FailingHosts  int           `json:"failing_hosts"`
    TotalChecks   int           `json:"total_checks"`
    ActiveAlerts  int           `json:"active_alerts"`
    Hosts         []HostStatus  `json:"hosts"`
    Summary       StatusSummary `json:"summary"`
}

type HostStatus struct {
    Hostname     string        `json:"hostname"`
    Status       string        `json:"status"`        // "OK", "WARNING", "CRITICAL", "UNKNOWN"
    StatusColor  string        `json:"status_color"`  // "green", "yellow", "red", "gray"
    LastCheck    time.Time     `json:"last_check"`
    Response     string        `json:"response"`      // e.g., "12.3ms", "200 OK", etc.
    Checks       []CheckStatus `json:"checks"`
    Contact      string        `json:"contact"`
}

type CheckStatus struct {
    Type         string    `json:"type"`          // "ping", "tcp", "http", etc.
    Status       string    `json:"status"`
    StatusColor  string    `json:"status_color"`
    Duration     string    `json:"duration"`
    Message      string    `json:"message"`
    LastRun      time.Time `json:"last_run"`
}

type StatusSummary struct {
    ByType    map[string]int `json:"by_type"`     // Count by check type
    ByStatus  map[string]int `json:"by_status"`   // Count by status
    RecentChanges []StatusChange `json:"recent_changes"`
}

type StatusChange struct {
    Hostname  string    `json:"hostname"`
    From      string    `json:"from"`
    To        string    `json:"to"`
    Timestamp time.Time `json:"timestamp"`
}

// GetMonitoringStatus connects to sysmon and requests JSON output
func (s *StatusService) GetMonitoringStatus() (*SysmonStatus, error) {
    // Connect to sysmon client port
    conn, err := net.DialTimeout("tcp", s.sysmonHost, 5*time.Second)
    if err != nil {
        return nil, fmt.Errorf("failed to connect to sysmon: %w", err)
    }
    defer conn.Close()

    // Request JSON output mode
    fmt.Fprintf(conn, "json\n")
    // Alternative: fmt.Fprintf(conn, "status --json\n")

    // Read JSON response
    var status SysmonStatus
    decoder := json.NewDecoder(conn)
    if err := decoder.Decode(&status); err != nil {
        return nil, fmt.Errorf("failed to parse JSON from sysmon: %w", err)
    }

    return &status, nil
}

// SysmonStatus mirrors the JSON output from sysmon daemon
// See SYSMON_JSON_OUTPUT_DESIGN.md for complete schema
type SysmonStatus struct {
    Daemon      DaemonInfo       `json:"daemon"`
    Hosts       []HostStatus     `json:"hosts"`
    Statistics  Stats            `json:"statistics"`
    SNMPTraps   *TrapInfo        `json:"snmp_traps,omitempty"`
}

type DaemonInfo struct {
    Version        string    `json:"version"`
    Uptime         int64     `json:"uptime_seconds"`
    StartTime      time.Time `json:"start_time"`
    CurrentTime    time.Time `json:"current_time"`
    PID            int       `json:"pid"`
    ConfigFile     string    `json:"config_file"`
    ConfigLoadTime time.Time `json:"config_load_time"`
}

type HostStatus struct {
    Hostname       string       `json:"hostname"`
    IPv4Address    string       `json:"ipv4_address,omitempty"`
    IPv6Address    string       `json:"ipv6_address,omitempty"`
    OverallStatus  string       `json:"overall_status"`
    StatusColor    string       `json:"status_color"`
    Contact        string       `json:"contact,omitempty"`
    Paused         bool         `json:"paused"`
    Checks         []CheckResult `json:"checks"`
}

type CheckResult struct {
    Type          string      `json:"type"`
    Port          int         `json:"port,omitempty"`
    Status        string      `json:"status"`
    LastCheckTime time.Time   `json:"last_check_time"`
    NextCheckTime time.Time   `json:"next_check_time"`
    CheckInterval int         `json:"check_interval_seconds"`
    ResponseTime  float64     `json:"response_time_ms,omitempty"`
    StatusMessage string      `json:"status_message,omitempty"`
    Result        interface{} `json:"result,omitempty"` // Type-specific result data
}

type Stats struct {
    TotalHosts      int            `json:"total_hosts"`
    HealthyHosts    int            `json:"healthy_hosts"`
    WarningHosts    int            `json:"warning_hosts"`
    CriticalHosts   int            `json:"critical_hosts"`
    TotalChecks     int            `json:"total_checks"`
    ChecksByType    map[string]int `json:"checks_by_type"`
    ChecksByStatus  map[string]int `json:"checks_by_status"`
}

type TrapInfo struct {
    RecentTraps  []Trap            `json:"recent_traps"`
    TrapSources  []TrapSource      `json:"trap_sources"`
    Summary      TrapSummary       `json:"summary"`
}

type Trap struct {
    SourceIP       string      `json:"source_ip"`
    SourceHostname string      `json:"source_hostname,omitempty"`
    Timestamp      time.Time   `json:"timestamp"`
    TrapType       string      `json:"trap_type"`
    Varbinds       []Varbind   `json:"varbinds"`
    Decoded        *TrapDecode `json:"decoded,omitempty"`
    MatchedHost    string      `json:"matched_host,omitempty"`
    AlertEnabled   bool        `json:"trap_alert_enabled"`
    AlertSent      bool        `json:"alert_sent"`
}

type Varbind struct {
    OID         string      `json:"oid"`
    Type        string      `json:"type"`
    Value       string      `json:"value"`
    Description string      `json:"description,omitempty"`
}

type TrapDecode struct {
    TrapName       string `json:"trap_name"`
    Description    string `json:"description"`
    Severity       string `json:"severity"`
    Category       string `json:"category"`
    Vendor         string `json:"vendor,omitempty"`
    Interface      string `json:"interface,omitempty"`
    InterfaceIndex int    `json:"interface_index,omitempty"`
}

type TrapSource struct {
    SourceIP   string `json:"source_ip"`
    Hostname   string `json:"hostname,omitempty"`
    TrapCount  int    `json:"trap_count"`
    LastTrap   time.Time `json:"last_trap"`
}

type TrapSummary struct {
    TotalTraps    int            `json:"total_traps_hour"`
    TrapsByType   map[string]int `json:"traps_by_type"`
    TrapsBySeverity map[string]int `json:"traps_by_severity"`
}

// GetDetailedHostStatus gets detailed status for a specific host
func (s *StatusService) GetDetailedHostStatus(hostname string) (*HostStatus, error) {
    // Get full status from sysmon
    status, err := s.GetMonitoringStatus()
    if err != nil {
        return nil, fmt.Errorf("failed to get monitoring status: %w", err)
    }

    // Find the requested host
    for _, host := range status.Hosts {
        if host.Hostname == hostname {
            return &host, nil
        }
    }

    return nil, fmt.Errorf("host %s not found", hostname)
}

// GetTrapsBySource gets SNMP traps from a specific source
func (s *StatusService) GetTrapsBySource(sourceIP string) ([]Trap, error) {
    status, err := s.GetMonitoringStatus()
    if err != nil {
        return nil, fmt.Errorf("failed to get monitoring status: %w", err)
    }

    if status.SNMPTraps == nil {
        return []Trap{}, nil
    }

    // Filter traps by source IP
    var filtered []Trap
    for _, trap := range status.SNMPTraps.RecentTraps {
        if trap.SourceIP == sourceIP {
            filtered = append(filtered, trap)
        }
    }

    return filtered, nil
}
```

**API Response Example:**

```json
{
  "uptime": "7 days, 3 hours",
  "total_hosts": 25,
  "healthy_hosts": 22,
  "failing_hosts": 3,
  "total_checks": 87,
  "active_alerts": 2,
  "hosts": [
    {
      "hostname": "web01.example.com",
      "status": "OK",
      "status_color": "green",
      "last_check": "2025-01-15T10:30:00Z",
      "response": "12.3ms",
      "contact": "admin@example.com",
      "checks": [
        {
          "type": "ping",
          "status": "OK",
          "status_color": "green",
          "duration": "12ms",
          "last_run": "2025-01-15T10:30:00Z"
        },
        {
          "type": "http",
          "status": "OK",
          "status_color": "green",
          "duration": "234ms",
          "message": "200 OK",
          "last_run": "2025-01-15T10:30:00Z"
        }
      ]
    },
    {
      "hostname": "db01.example.com",
      "status": "CRITICAL",
      "status_color": "red",
      "last_check": "2025-01-15T10:29:55Z",
      "response": "timeout",
      "contact": "dba@example.com",
      "checks": [
        {
          "type": "tcp",
          "status": "FAILED",
          "status_color": "red",
          "duration": "30s",
          "message": "Connection timeout",
          "last_run": "2025-01-15T10:29:55Z"
        }
      ]
    }
  ],
  "summary": {
    "by_type": {
      "ping": 25,
      "http": 18,
      "tcp": 32,
      "snmp": 12
    },
    "by_status": {
      "OK": 22,
      "WARNING": 0,
      "CRITICAL": 3
    }
  }
}
```

## Sysmon Socket Communication

The web UI talks to the same sysmon daemon socket that the CLI uses (typically `localhost:3355`). This provides real-time monitoring data.

**Communication Protocol:**

```
Client -> Server:  "status\n"
Server -> Client:  <text output with host statuses>

Client -> Server:  "status hostname.example.com\n"
Server -> Client:  <detailed status for specific host>
```

The Go application parses this text output and transforms it into structured JSON for the frontend, providing:

- Color-coded status indicators (green/yellow/red)
- Sortable/filterable tables
- Real-time updates via polling or WebSockets
- Historical trend visualization (optional)

**Why This Approach Works:**

1. **No daemon modifications needed** - Uses existing sysmon client protocol
2. **Real-time data** - Always shows current status from daemon
3. **Reliable** - If sysmon is down, the web UI shows a clear error
4. **Simple** - No need for separate monitoring data storage

## Nginx Configuration

```nginx
server {
    listen 80;
    server_name sysmon.example.com;

    # Redirect to HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name sysmon.example.com;

    ssl_certificate /etc/ssl/certs/sysmon.crt;
    ssl_certificate_key /etc/ssl/private/sysmon.key;

    # Proxy to FastCGI socket
    location / {
        fastcgi_pass unix:/var/run/sysmon-webui.sock;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
    }

    # WebSocket support (for live updates)
    location /ws {
        proxy_pass http://unix:/var/run/sysmon-webui.sock;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

## Systemd Service

```ini
# /etc/systemd/system/sysmon-webui.service
[Unit]
Description=Sysmon Web UI
After=network.target sysmond.service
Requires=sysmond.service

[Service]
Type=simple
User=sysmon
Group=sysmon
ExecStart=/usr/local/bin/sysmon-webui
Restart=always
RestartSec=5

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/run /var/lib/sysmon-webui /etc/sysmon.conf

[Install]
WantedBy=multi-user.target
```

## Security Considerations

### Authentication
1. **Session-based auth** with secure cookies
2. **RBAC** (Role-Based Access Control):
   - Admin: Full access
   - Operator: View + modify checks
   - Viewer: Read-only
3. **API tokens** for programmatic access

### Authorization
```go
// Middleware for role checking
func RequireRole(role string) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            user := getUserFromContext(r.Context())
            if user == nil || !user.HasRole(role) {
                http.Error(w, "Forbidden", http.StatusForbidden)
                return
            }
            next.ServeHTTP(w, r)
        })
    }
}
```

### Input Validation
1. **Strict validation** of all inputs
2. **Sanitization** of hostnames, IPs, commands
3. **Config validation** before applying
4. **Test mode** - validate without applying

### Audit Trail
1. **Log all changes** to audit_log table
2. **Include user, IP, timestamp**
3. **Store before/after state**

## Deployment

### Build Process

```makefile
# Makefile
.PHONY: build frontend backend install

all: build

frontend:
	cd frontend && npm install && npm run build

backend:
	cd backend && go build -o sysmon-webui cmd/server/main.go

build: frontend backend
	# Embed frontend into Go binary
	cd backend && \
	go build -ldflags "-X main.Version=$(VERSION)" \
	         -o ../sysmon-webui \
	         cmd/server/main.go

install: build
	install -m 0755 sysmon-webui /usr/local/bin/
	install -m 0644 systemd/sysmon-webui.service /etc/systemd/system/
	systemctl daemon-reload
	systemctl enable sysmon-webui
	systemctl start sysmon-webui

clean:
	rm -rf frontend/dist backend/sysmon-webui sysmon-webui
```

### Directory Structure

```
sysmon-webui/
├── backend/
│   ├── cmd/
│   │   └── server/
│   │       └── main.go
│   ├── internal/
│   │   ├── api/          # HTTP handlers
│   │   ├── service/      # Business logic
│   │   ├── parser/       # Config parser
│   │   ├── generator/    # Config generator
│   │   ├── db/           # Database access
│   │   └── models/       # Data models
│   ├── pkg/
│   │   └── client/       # Sysmon client
│   ├── go.mod
│   └── go.sum
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   ├── pages/
│   │   ├── hooks/
│   │   ├── services/
│   │   ├── types/
│   │   └── App.tsx
│   ├── public/
│   ├── package.json
│   ├── tsconfig.json
│   ├── tailwind.config.js
│   └── vite.config.ts
├── systemd/
│   └── sysmon-webui.service
├── nginx/
│   └── sysmon-webui.conf
├── Makefile
└── README.md
```

## Testing Strategy

### Backend Tests
```go
// Unit tests
func TestConfigParser(t *testing.T) {
    parser := parser.New()
    config, err := parser.Parse("testdata/sysmon.conf")
    assert.NoError(t, err)
    assert.Equal(t, 5, len(config.Hosts))
}

// Integration tests
func TestConfigReload(t *testing.T) {
    // Test full config save + reload cycle
}
```

### Frontend Tests
```tsx
// Component tests with React Testing Library
describe('HostForm', () => {
  it('validates required fields', async () => {
    render(<HostForm />)
    fireEvent.click(screen.getByText('Submit'))
    await waitFor(() => {
      expect(screen.getByText('Hostname is required')).toBeInTheDocument()
    })
  })
})
```

### E2E Tests
- **Playwright** for end-to-end testing
- Test critical flows: create host, add check, save config, reload

## Future Enhancements

1. **Real-time updates** via WebSockets
2. **Graphing** with Chart.js/Recharts for historical data
3. **Alerting dashboard** with real-time alert stream
4. **Multi-tenancy** support
5. **Config templates** for common setups
6. **Import/export** configs
7. **Bulk operations** (add multiple hosts from CSV)
8. **Mobile app** (React Native)
9. **Notifications** via push/email when config changes
10. **Integration tests** with actual sysmon daemon

## Performance Optimizations

1. **Caching**: Redis for status data
2. **Pagination**: Large host lists
3. **Debouncing**: Config validation
4. **Lazy loading**: Frontend routes
5. **Compression**: Gzip responses
6. **CDN**: Static assets

## Monitoring

1. **Prometheus metrics** endpoint
2. **Health checks** endpoint
3. **Log aggregation** (syslog/journald)
4. **Error tracking** (Sentry)

## Administrator Experience (UX First)

This design prioritizes **simplicity for administrators**, not simplicity of code. The goal is to make sysmon configuration accessible to anyone, not just those who can hand-edit config files.

### Key Administrator Benefits

**1. Visual Configuration Management**
- No need to remember sysmon config syntax
- Point-and-click interface for adding hosts and checks
- Type-specific forms that only show relevant fields
- Instant validation with clear error messages

**2. Safety and Confidence**
- **Validation before saving** - Catch errors before they break production
- **Automatic backups** - Every change creates a timestamped backup
- **Optimistic locking** - Prevents conflicting simultaneous changes
- **Test mode** - Validate without applying changes

**3. Visual Status Dashboard**
- Color-coded status at a glance (green/yellow/red)
- Real-time monitoring data from sysmon daemon
- Sortable, filterable tables
- Quick identification of problems
- Drill-down into specific hosts/checks

**4. Change Management**
- **Audit trail** - Every change logged with who/when/what
- **Config history** - View and restore previous versions
- **Diff view** - See exactly what changed between versions
- **Rollback** - Restore previous working configuration with one click

**5. No Learning Curve for New Administrators**
- Intuitive UI - if you can use a website, you can use this
- No need to SSH into server
- No need to learn sysmon config syntax
- No need to manually reload sysmon

### Example Administrator Workflows

**Adding a New Host (Without Web UI):**
```
1. SSH into server
2. vi /etc/sysmon.conf
3. Remember syntax: host hostname { contact ... }
4. Add host block with correct indentation
5. Add checks with correct syntax
6. Save file (:wq)
7. Validate syntax manually (or hope for best)
8. Find sysmon PID: ps aux | grep sysmond
9. Send SIGHUP: kill -HUP <pid>
10. Check logs: tail -f /var/log/syslog
```

**Adding a New Host (With Web UI):**
```
1. Open web browser
2. Click "Add Host"
3. Fill in form (hostname, contact, description)
4. Click "Add Check" → Select type → Fill in fields
5. Click "Save"
6. System automatically validates, backs up, saves, and reloads
7. See instant feedback if there are any issues
```

**Viewing Status (Without Web UI):**
```
1. SSH into server
2. sysmon
3. Read text output
4. grep/scroll to find specific host
5. Manually parse status codes
```

**Viewing Status (With Web UI):**
```
1. Open dashboard
2. See color-coded status grid
3. Sort by status to see failures first
4. Click host for details
5. See visual check results
```

## Summary

This design provides a complete, modern web interface for sysmon configuration management with:

✅ **Administrator-Friendly** - Point-and-click instead of config file editing
✅ **Safe** - Validation, backups, optimistic locking prevent mistakes
✅ **No Database** - Single source of truth is /etc/sysmon.conf
✅ **File-Based** - Simple architecture, no database to maintain
✅ **Optimistic Locking** - Prevents conflicting simultaneous edits
✅ **Clean architecture** - Well-organized Go backend, modern React frontend
✅ **Type-safe** - Go + TypeScript prevent runtime errors
✅ **Modern UI** - React + Tailwind CSS for beautiful, responsive interface
✅ **FastCGI deployment** - Efficient, production-ready, integrates with Nginx/Apache
✅ **Config versioning** - Track changes via timestamped backup files
✅ **Audit trail** - Log file tracks who changed what and when
✅ **Live reload** - SIGHUP to sysmon automatically
✅ **Validation** - Prevent bad configs before applying
✅ **Real-time Status** - Pretty display of sysmon daemon output
✅ **Responsive** - Works on desktop, tablet, and mobile
✅ **Secure** - Authentication, authorization, input validation

### Technical Simplicity

**Backend:**
- Single Go binary (includes embedded frontend)
- No database to install or maintain
- Reads/writes one file: `/etc/sysmon.conf`
- Backups automatically created on every change
- Talks to existing sysmon daemon socket

**Frontend:**
- Modern React SPA
- Embedded in Go binary (no separate deployment)
- Tailwind CSS for beautiful UI without custom CSS
- Real-time updates via API polling

**Deployment:**
- Single systemd service
- FastCGI socket for Nginx/Apache
- No migrations, no database schema updates
- Updates via simple binary replacement

### Administrator Simplicity

- **No config file editing** - Visual forms instead
- **No syntax to remember** - UI guides you
- **No manual validation** - Automatic before save
- **No manual backups** - Automatic on every change
- **No manual reload** - Automatic SIGHUP
- **No grep/awk to parse status** - Visual dashboard instead
- **No SSH required** - Web interface from anywhere
- **No fear of breaking production** - Validation + backups + rollback

The system is designed to be maintainable, extensible, and production-ready while providing an **excellent user experience** for administrators managing complex sysmon configurations. The code may be complex, but the **administrator experience is simple**.
