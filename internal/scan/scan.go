// Package scan ties collection, auditing, aggregation and pushing together into
// one cycle. It is the Go equivalent of scan.py's Scan.run.
package scan

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/vulnersCom/zabbix-threat-control/internal/aggregate"
	"github.com/vulnersCom/zabbix-threat-control/internal/audit"
	"github.com/vulnersCom/zabbix-threat-control/internal/collect"
	"github.com/vulnersCom/zabbix-threat-control/internal/model"
	"github.com/vulnersCom/zabbix-threat-control/internal/vulners"
	"github.com/vulnersCom/zabbix-threat-control/internal/zabbix/sender"
)

// Pusher sends metric batches to Zabbix (satisfied by *sender.Sender).
type Pusher interface {
	Send(ctx context.Context, metrics []sender.Metric) (*sender.Response, error)
}

// Options tunes one scan cycle.
type Options struct {
	Entities  aggregate.Entities
	NoPush    bool          // build data but don't send it
	PushDelay time.Duration // wait between LLD and data batches (Zabbix needs LLD applied first)
}

// Runner performs scan cycles.
type Runner struct {
	collector *collect.Collector
	auditor   vulners.Auditor
	pusher    Pusher
	opts      Options
	log       *slog.Logger
}

// New builds a Runner.
func New(c *collect.Collector, a vulners.Auditor, p Pusher, opts Options, log *slog.Logger) *Runner {
	if opts.PushDelay == 0 {
		opts.PushDelay = 5 * time.Minute
	}
	return &Runner{collector: c, auditor: a, pusher: p, opts: opts, log: log}
}

// Assess collects host inventory and audits it, returning per-host results
// without aggregating or pushing. Shared by RunOnce and the fix command.
func (r *Runner) Assess(ctx context.Context) ([]model.HostResult, error) {
	hosts, err := r.collector.Hosts(ctx)
	if err != nil {
		return nil, err
	}
	r.log.Info("collected hosts", "count", len(hosts))

	results := make([]model.HostResult, 0, len(hosts))
	for i, h := range hosts {
		res, err := audit.Audit(ctx, r.auditor, h)
		if err != nil {
			r.log.Error("audit failed, skipping host", "host", h.Name, "err", err)
			continue
		}
		r.log.Info("audited host", "n", fmt.Sprintf("%d/%d", i+1, len(hosts)), "host", h.Name, "score", res.Score, "bulletins", len(res.Bulletins))
		results = append(results, res)
	}
	return results, nil
}

// Cycle runs a full collect→audit→aggregate→push cycle and returns the audit
// results (so callers such as auto-fix can reuse them).
func (r *Runner) Cycle(ctx context.Context) ([]model.HostResult, error) {
	results, err := r.Assess(ctx)
	if err != nil {
		return nil, err
	}
	if len(results) == 0 {
		r.log.Warn("no auditable hosts found; nothing to do")
		return results, nil
	}

	payload := aggregate.Build(results, r.opts.Entities)

	if r.opts.NoPush {
		r.log.Info("nopush set: skipping delivery", "lld_items", len(payload.LLD), "data_items", len(payload.Data))
		return results, nil
	}
	if err := r.push(ctx, payload); err != nil {
		return results, err
	}
	return results, nil
}

// RunOnce executes a single scan cycle, discarding the results.
func (r *Runner) RunOnce(ctx context.Context) error {
	_, err := r.Cycle(ctx)
	return err
}

func (r *Runner) push(ctx context.Context, payload aggregate.Result) error {
	r.log.Info("pushing LLD", "items", len(payload.LLD))
	if _, err := r.pusher.Send(ctx, toMetrics(payload.LLD)); err != nil {
		return fmt.Errorf("push LLD: %w", err)
	}

	r.log.Info("waiting for LLD to apply", "delay", r.opts.PushDelay)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(r.opts.PushDelay):
	}

	r.log.Info("pushing data", "items", len(payload.Data))
	if _, err := r.pusher.Send(ctx, toMetrics(payload.Data)); err != nil {
		return fmt.Errorf("push data: %w", err)
	}
	r.log.Info("scan cycle complete")
	return nil
}

func toMetrics(items []aggregate.Item) []sender.Metric {
	out := make([]sender.Metric, len(items))
	for i, it := range items {
		out[i] = sender.Metric{Host: it.Host, Key: it.Key, Value: it.Value}
	}
	return out
}
