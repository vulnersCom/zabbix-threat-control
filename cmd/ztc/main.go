// Command ztc is the Vulners → Zabbix vulnerability scanner. It replaces the
// Python scan.py / prepare.py / fix.py trio with a single Go binary.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/vulnersCom/zabbix-threat-control/internal/aggregate"
	"github.com/vulnersCom/zabbix-threat-control/internal/collect"
	"github.com/vulnersCom/zabbix-threat-control/internal/config"
	"github.com/vulnersCom/zabbix-threat-control/internal/fix"
	"github.com/vulnersCom/zabbix-threat-control/internal/provision"
	"github.com/vulnersCom/zabbix-threat-control/internal/scan"
	"github.com/vulnersCom/zabbix-threat-control/internal/selfupdate"
	"github.com/vulnersCom/zabbix-threat-control/internal/vulners"
	"github.com/vulnersCom/zabbix-threat-control/internal/zabbix"
	"github.com/vulnersCom/zabbix-threat-control/internal/zabbix/agentget"
	"github.com/vulnersCom/zabbix-threat-control/internal/zabbix/sender"
)

// version is set at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd := os.Args[1]
	args := os.Args[2:]

	var err error
	switch cmd {
	case "scan":
		err = runScan(args)
	case "provision":
		err = runProvision(args)
	case "fix":
		err = runFix(args)
	case "version", "-v", "--version":
		fmt.Printf("ztc %s\n", version)
		if len(args) > 0 && (args[0] == "--check" || args[0] == "-c") {
			checkVersion()
		}
	case "upgrade":
		err = runUpgrade(args)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", cmd)
		usage()
		os.Exit(2)
	}
	if err != nil {
		slog.Error("command failed", "cmd", cmd, "err", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `ztc — Vulners vulnerability scanner for Zabbix

Usage:
  ztc scan       [--config F] [--once|--daemon] [--auto-fix] [--nopush] [--limit N] [--push-delay D]
  ztc provision  [--config F] [--all|--template --vhosts --dashboard]
  ztc fix        [--config F] (--host NAME (--all | --package PKG) | --package PKG) [--dry-run]
  ztc upgrade    [--version vX.Y.Z]   self-update the binary from GitHub Releases
  ztc version    [--check]            print version (and check for a newer release)

Environment overrides: VULNERS_API_KEY, ZABBIX_URL, ZABBIX_USER, ZABBIX_PASSWORD,
ZABBIX_TOKEN, ZABBIX_SERVER_FQDN, ZABBIX_SERVER_PORT.
`)
}

func newLogger(level string) *slog.Logger {
	lvl := slog.LevelInfo
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))
}

func loadConfig(path string) (config.Config, *slog.Logger, error) {
	cfg, err := config.Load(path)
	if err != nil {
		return cfg, newLogger("info"), err
	}
	return cfg, newLogger(cfg.LogLevel), nil
}

func entities(cfg config.Config) aggregate.Entities {
	return aggregate.Entities{
		HostsHost:      cfg.Entities.HostsHost,
		PackagesHost:   cfg.Entities.PackagesHost,
		BulletinsHost:  cfg.Entities.BulletinsHost,
		StatisticsHost: cfg.Entities.StatisticsHost,
	}
}

func newZabbix(ctx context.Context, cfg config.Config) (zabbix.Client, error) {
	return zabbix.New(ctx, zabbix.Options{
		URL:       cfg.Zabbix.URL,
		User:      cfg.Zabbix.User,
		Password:  cfg.Zabbix.Password,
		Token:     cfg.Zabbix.Token,
		VerifySSL: cfg.Zabbix.VerifySSL,
	}, cfg.Zabbix.Version)
}

func newFixer(cfg config.Config, zbx zabbix.Client, log *slog.Logger) *fix.Fixer {
	getter := agentget.New(cfg.Fix.AgentTimeout.D())
	return fix.New(zbx, getter, cfg.Fix, log)
}

// checkVersion prints whether a newer release exists (for `ztc version --check`).
func checkVersion() {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	latest, err := selfupdate.LatestVersion(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "version check failed: %v\n", err)
		return
	}
	if selfupdate.IsNewer(version, latest) {
		fmt.Printf("update available: %s (run: sudo ztc upgrade)\n", latest)
	} else {
		fmt.Printf("up to date (latest: %s)\n", latest)
	}
}

// checkForUpdate logs a warning if a newer release is available. Best-effort:
// it stays silent when the network/GitHub is unreachable.
func checkForUpdate(ctx context.Context, log *slog.Logger) {
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	latest, err := selfupdate.LatestVersion(cctx)
	if err != nil {
		return
	}
	if selfupdate.IsNewer(version, latest) {
		log.Warn("a newer ztc version is available", "current", version, "latest", latest, "hint", "sudo ztc upgrade")
	}
}

func runUpgrade(args []string) error {
	fs := flag.NewFlagSet("upgrade", flag.ExitOnError)
	ver := fs.String("version", "", "specific version to install (default: latest)")
	_ = fs.Parse(args)
	log := newLogger("info")
	target := "latest"
	if *ver != "" {
		target = *ver
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	log.Info("upgrading ztc", "current", version, "target", target)
	installed, err := selfupdate.Upgrade(ctx, *ver)
	if err != nil {
		return err
	}
	log.Info("upgrade complete", "installed", installed)
	fmt.Println("Restart the service to run the new version:  sudo systemctl restart ztc")
	return nil
}

func runScan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	cfgPath := fs.String("config", "", "path to YAML config")
	once := fs.Bool("once", true, "run a single scan cycle")
	daemon := fs.Bool("daemon", false, "run continuously on the configured schedule")
	autoFix := fs.Bool("auto-fix", false, "remediate problems acknowledged by trusted users after each cycle")
	nopush := fs.Bool("nopush", false, "build data but do not push to Zabbix")
	limit := fs.Int("limit", 0, "limit number of hosts fetched from Zabbix (0 = all)")
	pushDelay := fs.Duration("push-delay", 5*time.Minute, "delay between LLD and data batches")
	_ = fs.Parse(args)

	cfg, log, err := loadConfig(*cfgPath)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	zbx, err := newZabbix(ctx, cfg)
	if err != nil {
		return err
	}
	aud, err := vulners.New(cfg.Vulners)
	if err != nil {
		return err
	}
	push := sender.New(cfg.Zabbix.ServerFQDN, cfg.Zabbix.ServerPort, cfg.Vulners.Timeout.D())
	col := collect.New(zbx, []string{cfg.Entities.Template, cfg.Entities.TemplateWin}, *limit)

	runner := scan.New(col, aud, push, scan.Options{
		Entities:  entities(cfg),
		NoPush:    *nopush,
		PushDelay: *pushDelay,
	}, log)

	var fixer *fix.Fixer
	if *autoFix {
		fixer = newFixer(cfg, zbx, log)
	}

	cycle := func(ctx context.Context) {
		results, err := runner.Cycle(ctx)
		if err != nil {
			log.Error("scan cycle failed", "err", err)
			return
		}
		if fixer != nil && len(results) > 0 {
			applied, failed, ferr := fixer.AutoRemediate(ctx, results, cfg.Entities)
			if ferr != nil {
				log.Error("auto-fix failed", "err", ferr)
			} else if applied+failed > 0 {
				log.Info("auto-fix complete", "applied", applied, "failed", failed)
			}
		}
	}

	if *daemon {
		return runDaemon(ctx, cycle, cfg.Schedule.D(), log)
	}
	_ = once
	cycle(ctx)
	return nil
}

func runDaemon(ctx context.Context, cycle func(context.Context), interval time.Duration, log *slog.Logger) error {
	log.Info("starting scan daemon", "interval", interval)
	go checkForUpdate(ctx, log)
	cycle(ctx)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Info("shutting down")
			return nil
		case <-ticker.C:
			cycle(ctx)
		}
	}
}

func runProvision(args []string) error {
	fs := flag.NewFlagSet("provision", flag.ExitOnError)
	cfgPath := fs.String("config", "", "path to YAML config")
	all := fs.Bool("all", false, "create template, virtual hosts and dashboard")
	template := fs.Bool("template", false, "create the collection template")
	vhosts := fs.Bool("vhosts", false, "create the virtual hosts")
	dashboard := fs.Bool("dashboard", false, "create the dashboard")
	_ = fs.Parse(args)

	cfg, log, err := loadConfig(*cfgPath)
	if err != nil {
		return err
	}

	flags := provision.Flags{Template: *template, VHosts: *vhosts, Dashboard: *dashboard}
	if *all {
		flags = provision.Flags{Template: true, VHosts: true, Dashboard: true}
	}
	if !flags.Template && !flags.VHosts && !flags.Dashboard {
		return fmt.Errorf("nothing to do: pass --all or one of --template/--vhosts/--dashboard")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	zbx, err := newZabbix(ctx, cfg)
	if err != nil {
		return err
	}
	if v, err := zbx.Version(ctx); err == nil {
		log.Info("connected to Zabbix", "version", v)
	}
	return provision.New(zbx, cfg, log).Run(ctx, flags)
}

func runFix(args []string) error {
	fs := flag.NewFlagSet("fix", flag.ExitOnError)
	cfgPath := fs.String("config", "", "path to YAML config")
	host := fs.String("host", "", "visible name of the host to remediate")
	pkg := fs.String("package", "", "package-manager name to upgrade")
	all := fs.Bool("all", false, "remediate all vulnerable packages on --host")
	dryRun := fs.Bool("dry-run", false, "print what would be fixed without invoking agents")
	_ = fs.Parse(args)

	if *host == "" && *pkg == "" {
		return fmt.Errorf("specify --host with --all/--package, or --package to fix on all affected hosts")
	}
	if *host != "" && !*all && *pkg == "" {
		return fmt.Errorf("with --host, pass --all or --package PKG")
	}

	cfg, log, err := loadConfig(*cfgPath)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	zbx, err := newZabbix(ctx, cfg)
	if err != nil {
		return err
	}
	aud, err := vulners.New(cfg.Vulners)
	if err != nil {
		return err
	}
	col := collect.New(zbx, []string{cfg.Entities.Template, cfg.Entities.TemplateWin}, 0)
	runner := scan.New(col, aud, nil, scan.Options{Entities: entities(cfg)}, log)

	results, err := runner.Assess(ctx)
	if err != nil {
		return err
	}

	var targets []fix.Target
	switch {
	case *host != "" && *all:
		r, ok := fix.FindHost(results, *host)
		if !ok {
			return fmt.Errorf("host %q not found among audited hosts", *host)
		}
		targets = []fix.Target{fix.TargetForHost(r)}
	case *host != "" && *pkg != "":
		r, ok := fix.FindHost(results, *host)
		if !ok {
			return fmt.Errorf("host %q not found among audited hosts", *host)
		}
		targets = []fix.Target{{HostID: r.Host.HostID, Name: r.Host.Name, Packages: []string{*pkg}}}
	default: // --package only
		targets = fix.TargetsForPackage(results, *pkg)
		if len(targets) == 0 {
			return fmt.Errorf("no audited host is vulnerable to package %q", *pkg)
		}
	}

	if *dryRun {
		for _, t := range targets {
			log.Info("would fix", "host", t.Name, "packages", t.Packages)
		}
		return nil
	}

	fixer := newFixer(cfg, zbx, log)
	applied, failed := fixer.Apply(ctx, targets)
	log.Info("fix complete", "applied", applied, "failed", failed)
	if failed > 0 {
		return fmt.Errorf("%d fix operation(s) failed", failed)
	}
	return nil
}
