// Command opsctl is the audited operator CLI. It's a CLI rather than a set
// of new HTTP routes specifically to avoid touching the frozen
// api/openapi.yaml contract.
//
// opsctl is NOT credential-gated: the old admin-key check was vacuous — the
// binary reads the platform's own --config file (Mongo URI/DB, hot keys), so
// whoever can run it already holds every secret the check would have
// compared against. Access control is therefore filesystem/host access to the
// config, exactly as for `platform` itself. Every subcommand still:
//   - connects to the SAME MongoDB (or in-memory store, for
//     PERSISTENCE_MODE=memory dev) the running platform server uses, so its
//     writes are immediately visible to it;
//   - records exactly one audit_logs entry per invocation (category "opsctl",
//     actor = "opsctl:"+an attributable label from --actor or the OS user),
//     whether it succeeds or fails — see commands.go's opsCtx.audited.
//
// Usage:
//
//	opsctl --config <path> [--actor <label>] ipfs retry --id=<id> --file=<path>
//	opsctl --config <path> [--actor <label>] ipfs restore-local --id=<id>
//
// Every subcommand reads the platform's normal --config YAML file
// (internal/config), same as `platform`/`reindex` — Mongo URI/DB, program
// addresses, key material, etc.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/user"
	"strings"
	"time"

	"github.com/rwa-platform/server/internal/auditlog"
	"github.com/rwa-platform/server/internal/config"
	"github.com/rwa-platform/server/internal/dal"
	"github.com/rwa-platform/server/internal/dal/memory"
	"github.com/rwa-platform/server/internal/dal/mongodb"
	"github.com/rwa-platform/server/internal/dal/repository"
	"github.com/rwa-platform/server/internal/ipfs"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	top := flag.NewFlagSet("opsctl", flag.ContinueOnError)
	configPath := top.String("config", "", "path to the YAML configuration file (required)")
	actorFlag := top.String("actor", "", "attributable label recorded as the audit actor for this invocation (defaults to the OS user, else \"opsctl\")")
	if err := top.Parse(args); err != nil {
		return 2
	}
	rest := top.Args()
	if len(rest) < 2 {
		printUsage()
		return 2
	}
	group, action, rest := rest[0], rest[1], rest[2:]

	if *configPath == "" {
		fmt.Fprintln(os.Stderr, "opsctl: --config <path> is required")
		return 2
	}
	cfg, err := config.LoadFile(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "opsctl: config: %v\n", err)
		return 1
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	repos, closeRepos, err := connectRepos(ctx, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "opsctl: connecting to storage: %v\n", err)
		return 1
	}
	defer closeRepos()

	o := opsCtx{
		ctx: ctx, repos: repos, audit: auditlog.New(repos.AuditLogs),
		actor: auditActor(*actorFlag), out: os.Stdout,
	}

	if err := dispatch(o, cfg, group, action, rest); err != nil {
		fmt.Fprintf(os.Stderr, "opsctl: %v\n", err)
		return 1
	}
	return 0
}

// auditActor derives the audit-actor label for an invocation. opsctl is not
// credential-gated (see the package doc), so this is purely for attribution,
// not authorization: an explicit --actor wins, else the OS user, else the
// literal "opsctl". Always prefixed "opsctl:" so opsctl-originated audit
// entries are distinguishable from the platform server's own actors.
func auditActor(actorFlag string) string {
	label := strings.TrimSpace(actorFlag)
	if label == "" {
		if u, err := user.Current(); err == nil && strings.TrimSpace(u.Username) != "" {
			label = strings.TrimSpace(u.Username)
		}
	}
	if label == "" {
		label = "opsctl"
	}
	return "opsctl:" + label
}

// connectRepos mirrors cmd/reindex's storage wiring: PERSISTENCE_MODE=memory
// uses an in-memory store (dev only — never durable, matches
// cmd/platform's own refusal to allow it in production), otherwise connects
// to the configured MongoDB and fails loudly if it's unreachable rather
// than silently falling back to a throwaway in-memory store the way
// cmd/platform's REQUEST-SERVING path does — an ops tool operating on the
// wrong store is far worse than one that just refuses to start.
func connectRepos(ctx context.Context, cfg config.Config) (*repository.Repositories, func(), error) {
	if cfg.PersistenceMode == "memory" {
		return memory.New(), func() {}, nil
	}
	client, err := dal.Connect(ctx, cfg.MongoURI)
	if err != nil {
		return nil, nil, err
	}
	return mongodb.New(client.Database(cfg.MongoDB)), func() { _ = client.Disconnect(context.Background()) }, nil
}

// buildReplicationManager mirrors cmd/platform's newIPFSReplicationManager
// (main.go) — duplicated rather than imported since that helper is
// unexported in package main of a different command.
func buildReplicationManager(cfg config.Config, repos *repository.Repositories) (*ipfs.ReplicationManager, error) {
	if cfg.IPFSAPIURL == "" {
		return nil, fmt.Errorf("IPFS_API_URL is not configured")
	}
	local := ipfs.NewKuboClient(cfg.IPFSAPIURL)
	var backups []ipfs.Destination
	if cfg.IPFSBackupArchiveDir != "" {
		archive, err := ipfs.NewFileArchiveClient(cfg.IPFSBackupArchiveDir)
		if err != nil {
			return nil, err
		}
		backups = append(backups, ipfs.Destination{Name: "archive", Client: archive})
	}
	if cfg.IPFSBackupKuboURL != "" {
		backups = append(backups, ipfs.Destination{Name: "backup-kubo", Client: ipfs.NewKuboClient(cfg.IPFSBackupKuboURL)})
	}
	if len(backups) == 0 {
		return nil, fmt.Errorf("no backup destination configured (IPFS_BACKUP_ARCHIVE_DIR or IPFS_BACKUP_KUBO_URL)")
	}
	return ipfs.NewReplicationManager(local, backups, cfg.IPFSReplicationThreshold, repos.Publications), nil
}

func dispatch(o opsCtx, cfg config.Config, group, action string, args []string) error {
	cmd := group + " " + action
	switch cmd {
	case "ipfs retry":
		fs := flag.NewFlagSet("ipfs retry", flag.ContinueOnError)
		id := fs.String("id", "", "publication id")
		file := fs.String("file", "", "path to the original content — MUST hash to the record's already-recorded CID")
		if err := fs.Parse(args); err != nil {
			return err
		}
		if *id == "" || *file == "" {
			return fmt.Errorf("ipfs retry requires --id and --file")
		}
		data, err := os.ReadFile(*file)
		if err != nil {
			return err
		}
		rm, err := buildReplicationManager(cfg, o.repos)
		if err != nil {
			return err
		}
		return runIPFSRetry(o, rm, *id, data)

	case "ipfs restore-local":
		fs := flag.NewFlagSet("ipfs restore-local", flag.ContinueOnError)
		id := fs.String("id", "", "publication id")
		if err := fs.Parse(args); err != nil {
			return err
		}
		if *id == "" {
			return fmt.Errorf("ipfs restore-local requires --id")
		}
		rm, err := buildReplicationManager(cfg, o.repos)
		if err != nil {
			return err
		}
		return runIPFSRestoreLocal(o, rm, *id)

	case "indexer probe":
		// Read-only: safe against a live deployment.
		return runIndexerProbe(o.ctx, cfg, o.repos.IndexerCheckpoints)

	default:
		printUsage()
		return fmt.Errorf("unknown command %q", strings.TrimSpace(group+" "+action))
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, `opsctl --config <path> [--actor <label>] <group> <action> [flags]

  ipfs retry          --id=<id> --file=<path>
  ipfs restore-local  --id=<id>
  indexer probe       diagnose why chain_events is empty (read-only)

opsctl is not credential-gated — it reads the platform's own --config file, so host/file
access to that config IS the access boundary. --actor only labels the audit trail.`)
}
