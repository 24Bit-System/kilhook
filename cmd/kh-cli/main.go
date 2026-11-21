// Command kh-cli runs one .kh request through the whole loop: send, validate
// against an OpenAPI contract, fuzz, diff against a baseline, and print one
// report. It is the headless half of the product; cmd/kh-app calls the same
// engine from a desktop window.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/24Bit-System/kilhook/internal/engine"
	"github.com/24Bit-System/kilhook/internal/report"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	root := newRootCmd()
	root.SetOut(os.Stdout)
	root.SetErr(os.Stderr)

	if err := root.ExecuteContext(ctx); err != nil {
		var ee *exitError
		if errors.As(err, &ee) {
			os.Exit(ee.code)
		}
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}
}

type exitError struct{ code int }

func (e *exitError) Error() string { return fmt.Sprintf("exit %d", e.code) }

func newRootCmd() *cobra.Command {
	opts := &engine.Options{}
	var htmlOut string
	var jsonOut bool

	root := &cobra.Command{
		Use:           "kh-cli",
		Short:         "Run a .kh request through validate → fuzz → diff → report",
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       report.Version,
	}

	runCmd := &cobra.Command{
		Use:   "run <file.kh>",
		Short: "Run the full loop for one request file",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			rep, err := engine.Run(ctx, args[0], *opts, func(format string, args ...any) {
				cmd.PrintErr(fmt.Sprintf(format, args...))
			})
			if err != nil {
				return err
			}

			if jsonOut {
				data, err := rep.JSON()
				if err != nil {
					return err
				}
				cmd.Print(string(data))
				cmd.Print("\n")
			} else {
				cmd.Print(rep.Text())
				cmd.Print("\n")
			}

			if htmlOut != "" {
				html, err := rep.HTML()
				if err != nil {
					return err
				}
				if dir := filepath.Dir(htmlOut); dir != "" && dir != "." {
					if err := os.MkdirAll(dir, 0o755); err != nil {
						return fmt.Errorf("creating %s: %w", dir, err)
					}
				}
				if err := os.WriteFile(htmlOut, html, 0o644); err != nil {
					return fmt.Errorf("writing %s: %w", htmlOut, err)
				}
				cmd.PrintErr(fmt.Sprintf("report written to %s\n", htmlOut))
			}

			if rep.ExitCode != 0 {
				return &exitError{code: rep.ExitCode}
			}
			return nil
		},
	}

	f := runCmd.Flags()
	f.StringVar(&opts.EnvName, "env", "", "environment name; loads .kilhook/env/<name>.yaml next to the request file")
	f.StringVar(&opts.EnvFile, "env-file", "", "explicit environment YAML file")
	f.BoolVar(&opts.AllowNonLocal, "allow-nonlocal", false, "allow fuzzing a host that is not localhost")
	f.StringVar(&opts.Baseline, "baseline", "", "baseline response file (default: spec.baseline, else .kilhook/baselines/<name>.json)")
	f.BoolVar(&opts.UpdateBaseline, "update-baseline", false, "store this response as the new last-known-good baseline")
	f.BoolVar(&opts.NoFuzz, "no-fuzz", false, "skip the fuzz pass even if the file declares one")
	f.BoolVar(&opts.NoSpec, "no-spec", false, "skip OpenAPI validation even if the file declares a spec")
	f.BoolVar(&opts.NoDiff, "no-diff", false, "skip baseline comparison")
	f.StringVar(&htmlOut, "html", "", "write the standalone HTML report to this path")
	f.BoolVar(&jsonOut, "json", false, "print the report as JSON")
	f.IntVar(&opts.TimeoutMS, "timeout", 0, "request timeout in ms (overrides the file)")
	f.IntVar(&opts.MaxRequests, "max-requests", 0, "cap on fuzz requests (overrides the file)")
	f.Float64Var(&opts.RateLimit, "rate-limit", 0, "global fuzz rate in req/s (overrides the file)")
	f.IntVar(&opts.PerHost, "per-host", 0, "concurrent fuzz requests per host (overrides the file)")
	f.BoolVar(&opts.Timing, "timing", false, "enable the advisory timing heuristic (off by default)")
	f.BoolVar(&opts.Insecure, "insecure", false, "skip TLS certificate verification")

	root.AddCommand(runCmd)
	return root
}
