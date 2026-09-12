// Copyright 2026 Thingz LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"crypto"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/urfave/cli/v3"

	"github.com/thingzio/devproof/internal/version"
	"github.com/thingzio/devproof/pkg/bundle"
	"github.com/thingzio/devproof/pkg/credentials"
	"github.com/thingzio/devproof/pkg/devproof"
	"github.com/thingzio/devproof/pkg/evidence"
	"github.com/thingzio/devproof/pkg/fault"
)

// envPrefix namespaces every environment variable.
//
// Prefixed and only prefixed: an unprefixed name like TIMEOUT or FORMAT
// collides with shells, CI runners, and unrelated tooling, and picking one up
// by accident changes behavior nobody asked to change.
const envPrefix = "DEVPROOF_"

// App is the command tree plus the state a run needs.
type App struct {
	Streams Streams
	printer *Printer
	config  *Config
	// timeout is resolved once, in configure, so that the deadline actually
	// applied and the deadline reported under --debug cannot disagree.
	timeout time.Duration
	// interrupted records whether a signal arrived, which decides whether a
	// cancellation exits 130 or takes the operation's own code (DP-023). It
	// is written by the signal goroutine and read on the failure path, so it
	// is atomic rather than a plain bool.
	interrupted atomic.Bool
}

// Run executes the command line and returns a process exit code.
//
// It never calls os.Exit itself. Returning the code lets main decide, and
// lets a test run the whole command tree in-process and assert on it.
func Run(ctx context.Context, args []string, streams Streams) int {
	app := &App{
		Streams: streams,
		printer: &Printer{Streams: streams, Format: FormatText},
		config:  &Config{},
	}

	// Signals are watched through their own channel rather than through
	// signal.NotifyContext, because the exit code has to distinguish why the
	// context ended. NotifyContext only reports that it is done, so a caller
	// who canceled their own context would have been reported as killed by
	// SIGINT — exit 130 — when nobody pressed anything. Exit 130 is a claim
	// about a signal, so it is only made when a signal actually arrived
	// (DP-023).
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(signals)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// The watcher exits with the run, so a long-lived process embedding this
	// does not accumulate one goroutine per invocation.
	watching := make(chan struct{})
	defer close(watching)
	go func() {
		select {
		case <-signals:
			app.interrupted.Store(true)
			cancel()
		case <-watching:
		}
	}()

	if err := app.command().Run(ctx, args); err != nil {
		return app.printer.Failure(err, app.interrupted.Load())
	}
	return fault.ExitSuccess
}

// onUsageError converts a flag-parsing failure into a typed usage error.
//
// Without it the library prints "Incorrect Usage", dumps the full help to
// stdout, and returns an untyped error that classifies as internal — so a
// misspelled flag would report exit 10 ("internal error") and push two
// kilobytes of help text into whatever the caller piped stdout to. Returning
// a typed error routes the failure through the one path that renders it:
// stderr in text mode, a JSON envelope in JSON mode, exit 2 either way.
func onUsageError(_ context.Context, _ *cli.Command, err error, _ bool) error {
	if err == nil {
		return nil
	}
	return usageError(err.Error() + "; run with --help for usage")
}

func (a *App) command() *cli.Command {
	commands := []*cli.Command{
		a.lockCommand(),
		a.buildCommand(),
		a.verifyCommand(),
		a.expandCommand(),
		a.copyCommand(),
		a.inspectCommand(),
		a.versionCommand(),
	}
	// Applied here rather than in each constructor: the hook is per-command
	// with no inheritance, and a command that forgot it would silently get the
	// library's behavior back.
	for _, command := range commands {
		command.OnUsageError = onUsageError
	}

	return &cli.Command{
		Name:  "devproof",
		Usage: "build, verify, and expand immutable bundles",
		Description: "DevProof turns files from local directories and Git repositories " +
			"into immutable OCI artifacts that can be verified, redistributed, and " +
			"expanded back into their canonical filesystem form.",
		Version: version.Version(),
		Flags:   a.globalFlags(),
		// Help and usage go through the injected streams rather than the
		// process ones, so an embedding caller can capture them and a test can
		// assert that they land where they are supposed to.
		//
		// Requested help is a result and goes to stdout; a usage error is a
		// diagnostic and goes to stderr.
		Writer:                a.Streams.Out,
		ErrWriter:             a.Streams.Err,
		EnableShellCompletion: true,
		OnUsageError:          onUsageError,
		Before: func(ctx context.Context, cmd *cli.Command) (context.Context, error) {
			return ctx, a.configure(cmd)
		},
		Commands: commands,
		Action: func(_ context.Context, cmd *cli.Command) error {
			// An unrecognized first argument reaches the root action rather
			// than the library's not-found path, because the root has an
			// action at all. Left alone it prints help and exits zero, so a
			// typo in a CI script succeeds silently.
			if name := cmd.Args().First(); name != "" {
				return usageError(fmt.Sprintf(
					"unknown command %q; run `devproof --help` for the command list", name))
			}
			// Running bare prints help and succeeds: asking a tool what it
			// does is not an error.
			return cli.ShowAppHelp(cmd)
		},
	}
}

func (a *App) globalFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:    "config",
			Usage:   "configuration file; defaults to the per-user config directory",
			Sources: cli.EnvVars(envPrefix + "CONFIG"),
		},
		&cli.StringFlag{
			Name:    "format",
			Usage:   "result rendering: text or json",
			Value:   string(FormatText),
			Sources: cli.EnvVars(envPrefix + "FORMAT"),
		},
		&cli.BoolFlag{
			Name:    "quiet",
			Aliases: []string{"q"},
			Usage:   "print only the primary resulting digest or path",
			Sources: cli.EnvVars(envPrefix + "QUIET"),
		},
		&cli.BoolFlag{
			Name:    "verbose",
			Usage:   "include informational diagnostics on stderr",
			Sources: cli.EnvVars(envPrefix + "VERBOSE"),
		},
		&cli.BoolFlag{
			Name:    "debug",
			Usage:   "include sanitized debug diagnostics on stderr",
			Sources: cli.EnvVars(envPrefix + "DEBUG"),
		},
		&cli.DurationFlag{
			Name:    "timeout",
			Usage:   "overall operation timeout",
			Value:   30 * time.Minute,
			Sources: cli.EnvVars(envPrefix + "TIMEOUT"),
		},
		&cli.BoolFlag{
			Name:    "no-color",
			Usage:   "disable color; NO_COLOR is also honored",
			Sources: cli.EnvVars(envPrefix + "NO_COLOR"),
		},
		&cli.BoolFlag{
			Name:  "non-interactive",
			Usage: "prohibit prompts and browser interaction",
			// Nothing in DevProof prompts, opens a browser, or reads a
			// terminal: the SDK is forbidden from doing so (DP-001) and the
			// CLI has no interactive flow. The flag is therefore satisfied
			// unconditionally today, and exists so that a script can assert
			// the guarantee rather than discover later that some path started
			// prompting. Honored from CI as well, because a CI run that blocks
			// on a prompt hangs until someone notices rather than failing.
			//
			// Any future interactive path must read this flag before
			// prompting. The test below is what keeps that honest.
			Sources: cli.EnvVars(envPrefix+"NON_INTERACTIVE", "CI"),
		},
		&cli.BoolFlag{
			Name:    "insecure-registry",
			Usage:   "use plain HTTP for registries (sends credentials in the clear)",
			Sources: cli.EnvVars(envPrefix + "INSECURE_REGISTRY"),
		},
	}
}

// configure loads the configuration file and applies global settings.
//
// A flag or environment variable always wins over the file. urfave/cli reports
// whether a value was actually supplied, which is what makes the distinction
// possible: a flag sitting at its default has not been set, so the file's
// value applies, and one that was set has, so it does not.
func (a *App) configure(cmd *cli.Command) error {
	path, explicit := cmd.String("config"), cmd.IsSet("config")
	if !explicit {
		path = defaultConfigPath()
	}
	if path != "" {
		config, err := loadConfig(path, explicit)
		if err != nil {
			return err
		}
		a.config = config
	}

	format := Format(cmd.String("format"))
	if !cmd.IsSet("format") && a.config.Format != "" {
		format = Format(a.config.Format)
	}
	switch format {
	case FormatText, FormatJSON:
	default:
		return fault.New(fault.CodeInvalidInput, "cli",
			fmt.Sprintf("unknown output format %q; use text or json", format))
	}

	quiet := cmd.Bool("quiet")
	if quiet && format == FormatJSON {
		// Both would mean two different answers to "what goes on stdout".
		return fault.New(fault.CodeInvalidInput, "cli",
			"--quiet and --format json are mutually exclusive")
	}

	timeout := cmd.Duration("timeout")
	if !cmd.IsSet("timeout") && a.config.Timeout != "" {
		parsed, err := time.ParseDuration(a.config.Timeout)
		if err != nil {
			return fault.Wrap(fault.CodeInvalidInput, "cli",
				"the configured timeout is not a duration", err)
		}
		timeout = parsed
	}
	a.timeout = timeout

	a.printer.Format = format
	a.printer.Quiet = quiet
	a.printer.Verbose = cmd.Bool("verbose") || a.config.Verbose
	a.printer.Debug = cmd.Bool("debug") || a.config.Debug
	a.printer.NoColor = cmd.Bool("no-color") || a.config.NoColor

	if a.printer.Debug {
		a.reportSettings(cmd, path)
	}
	return nil
}

// reportSettings prints the effective global settings and where each came
// from.
//
// "Why did it do that" is almost always a precedence question, and answering
// it by reasoning about three layers is exactly the kind of thing nobody gets
// right under pressure.
//
// Only the global settings are reported here. A command's own flags have not
// been parsed when the root runs, so reporting them would print the
// configured value while the command went on to use the flag — a debug dump
// that misleads is worse than none. Those are reported by the code that
// resolves them, in [App.settingSource].
//
// Secrets are never printed: a path to trust material is a setting, the
// material itself is not.
func (a *App) reportSettings(cmd *cli.Command, configPath string) {
	a.printer.Info("config file: %s", orNone(configPath))
	a.printer.Info("format: %s (%s)", a.printer.Format,
		settingSource(cmd, "format", a.config.Format != ""))
	a.printer.Info("timeout: %s (%s)", a.timeout,
		settingSource(cmd, "timeout", a.config.Timeout != ""))
}

// settingSource names where a resolved value came from.
func settingSource(cmd *cli.Command, flag string, fromConfig bool) string {
	switch {
	case cmd.IsSet(flag):
		// A flag and its environment variable are the same setting to
		// urfave/cli, so they are reported together rather than guessed
		// between.
		return "flag or " + envPrefix + strings.ToUpper(strings.ReplaceAll(flag, "-", "_"))
	case fromConfig:
		return "config"
	default:
		return "default"
	}
}

// reportSetting logs one resolved per-command setting.
func (a *App) reportSetting(cmd *cli.Command, name, flag, value string, fromConfig bool) {
	if !a.printer.Debug {
		return
	}
	a.printer.Info("%s: %s (%s)", name, orNone(value), settingSource(cmd, flag, fromConfig))
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

// setting returns a string flag's value, falling back to the file.
func (a *App) setting(cmd *cli.Command, flag, fromConfig string) string {
	if cmd.IsSet(flag) {
		return cmd.String(flag)
	}
	if fromConfig != "" {
		return fromConfig
	}
	return cmd.String(flag)
}

// client builds an SDK client from the resolved flags.
//
// Constructed per command rather than once, so that a flag only that command
// accepts — a policy, a signing mode — is visible here without every command
// having to know about it.
func (a *App) client(cmd *cli.Command, extra ...devproof.Option) (*devproof.Client, error) {
	// Registry credentials come from the Docker configuration, so that
	// `docker login` — which every operator and CI runner has already run —
	// is all the setup there is. The provider is SDK-public: the CLI gets no
	// capability here that an embedding application cannot have (DP-001).
	provider := credentials.NewDocker(credentials.DockerOptions{Logger: a.logger()})

	opts := []devproof.Option{
		devproof.WithLogger(a.logger()),
		devproof.WithRegistryCredentials(provider),
	}
	if cmd.Bool("insecure-registry") {
		a.printer.Warn("registry transport is plain HTTP; credentials and content are sent in the clear")
		opts = append(opts, devproof.WithInsecureRegistry(provider))
	}
	opts = append(opts, extra...)
	return devproof.New(opts...)
}

// withTimeout applies the overall operation deadline, resolved by configure.
func (a *App) withTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	if a.timeout <= 0 {
		// Zero does not silently mean unbounded: an operation with no
		// deadline is one that can hang a CI job forever.
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, a.timeout)
}

// signingOptions turns signing flags into client options.
//
// Keyless is the default when signing is asked for. An explicit key file is
// for air-gapped builds and for callers who already manage keys.
func (a *App) signingOptions(cmd *cli.Command) ([]devproof.Option, error) {
	keyPath := cmd.String("key")
	if keyPath == "" {
		fulcio := a.setting(cmd, "fulcio-url", a.config.FulcioURL)
		rekor := a.setting(cmd, "rekor-url", a.config.RekorURL)
		a.reportSetting(cmd, "signing", "key", "keyless", false)
		a.reportSetting(cmd, "fulcio url", "fulcio-url", fulcio, a.config.FulcioURL != "")
		a.reportSetting(cmd, "rekor url", "rekor-url", rekor, a.config.RekorURL != "")
		return []devproof.Option{devproof.WithSigstore(evidence.SigstoreOptions{
			FulcioURL: fulcio,
			RekorURL:  rekor,
		})}, nil
	}
	a.reportSetting(cmd, "signing", "key", "key "+keyPath, false)

	data, err := os.ReadFile(keyPath) //nolint:gosec // operator-supplied key path
	if err != nil {
		return nil, fault.Wrap(fault.CodeInvalidInput, "cli", "reading the signing key", err)
	}
	signer, err := evidence.ParsePrivateKeyPEM(data)
	if err != nil {
		return nil, err
	}
	attester, err := evidence.NewKeyAttester(signer)
	if err != nil {
		return nil, err
	}
	return []devproof.Option{devproof.WithAttester(attester)}, nil
}

// verificationOptions turns verification flags into client options.
func (a *App) verificationOptions(cmd *cli.Command) ([]devproof.Option, error) {
	var opts []devproof.Option

	if keys := cmd.StringSlice("key"); len(keys) > 0 {
		var publicKeys []crypto.PublicKey
		for _, path := range keys {
			data, err := os.ReadFile(path) //nolint:gosec // operator-supplied key path
			if err != nil {
				return nil, fault.Wrap(fault.CodeInvalidInput, "cli", "reading a trusted key", err)
			}
			key, err := evidence.ParsePublicKeyPEM(data)
			if err != nil {
				return nil, err
			}
			publicKeys = append(publicKeys, key)
		}
		verifier, err := evidence.NewKeyVerifier(publicKeys...)
		if err != nil {
			return nil, err
		}
		return append(opts, devproof.WithVerifier(verifier)), nil
	}

	sigstoreOpts := evidence.SigstoreOptions{}
	root := a.setting(cmd, "trust-root", a.config.TrustRoot)
	a.reportSetting(cmd, "trust root", "trust-root", root, a.config.TrustRoot != "")
	if root != "" {
		data, err := os.ReadFile(root) //nolint:gosec // operator-supplied trust root
		if err != nil {
			return nil, fault.Wrap(fault.CodeInvalidInput, "cli", "reading the trust root", err)
		}
		sigstoreOpts.TrustedRootJSON = data
	}
	if cmd.Bool("offline") && len(sigstoreOpts.TrustedRootJSON) == 0 {
		// Offline verification with no trust material cannot establish
		// anything. Failing here says so where it can be fixed, rather than
		// at the first network call.
		return nil, fault.New(fault.CodeInvalidInput, "cli",
			"--offline needs --trust-root; without trust material nothing can be verified")
	}
	return append(opts, devproof.WithSigstore(sigstoreOpts)), nil
}

// logger routes SDK diagnostics to stderr, and only when asked for.
func (a *App) logger() *slogLogger {
	return newStderrLogger(a.Streams.Err, a.printer.Verbose, a.printer.Debug)
}

func (a *App) versionCommand() *cli.Command {
	return &cli.Command{
		Name:  "version",
		Usage: "show version and supported format versions",
		// No I/O, no configuration read, no network: asking a binary what it
		// is must work in any environment.
		Action: func(_ context.Context, _ *cli.Command) error {
			formats := make([]string, 0, len(bundle.SupportedFormats()))
			for _, format := range bundle.SupportedFormats() {
				formats = append(formats, format.String())
			}
			result := map[string]any{
				"version":          version.Version(),
				"commit":           version.Commit(),
				"supportedFormats": formats,
			}
			return a.printer.Result("Version", result, version.Version(), func(w io.Writer) {
				Field(w, "version", version.Version())
				Field(w, "commit", version.Commit())
				Field(w, "formats", strings.Join(formats, ", "))
			})
		},
	}
}
