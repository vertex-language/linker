package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/vertex-language/linker/macho/codesign"
)

func main() {
	var (
		sign     = flag.String("sign", "", `signing identity; "-" for ad-hoc, or a cert name/path`)
		certPath = flag.String("cert", "", "PEM certificate (+chain) for production signing")
		keyPath  = flag.String("key", "", "PEM private key for production signing")
		ident    = flag.String("identifier", "", "explicit code-signing identifier")
		team     = flag.String("team-identifier", "", "team identifier")
		ents     = flag.String("entitlements", "", "path to entitlements plist (XML)")
		force    = flag.Bool("f", false, "replace any existing signature")
		hardened = flag.Bool("o", false, "enable hardened runtime (CS_RUNTIME)")

		// Verbosity flags — each level is a superset of the previous.
		v1 = flag.Bool("v", false, "verbose: show arch, format, identifier")
		v2 = flag.Bool("vv", false, "more verbose: CodeDirectory fields, blob sizes, CDHash, flags")
		v3 = flag.Bool("vvv", false, "maximum verbosity: full Mach-O header, every load command, every page hash, timing")
	)
	flag.Parse()

	if *sign == "" || flag.NArg() < 1 {
		fmt.Fprintln(os.Stderr,
			"usage: codesigner --sign - [-f] [-o] [-v|-vv|-vvv] [--identifier id] <binary> ...")
		os.Exit(2)
	}

	// Derive a single integer level; -vvv wins over -vv wins over -v.
	verbosity := 0
	switch {
	case *v3:
		verbosity = codesign.VerbosityV3
	case *v2:
		verbosity = codesign.VerbosityV2
	case *v1:
		verbosity = codesign.VerbosityV1
	}

	logger := codesign.NewLogger(os.Stderr, verbosity)

	opts := codesign.Options{
		Identifier: *ident,
		TeamID:     *team,
		Force:      *force,
		Hardened:   *hardened,
		Logger:     logger,
	}

	if *sign != "-" { // production: load certificate + key
		if *certPath == "" || *keyPath == "" {
			fmt.Fprintln(os.Stderr, "production signing requires --cert and --key (PEM)")
			os.Exit(2)
		}
		id, err := codesign.LoadIdentityPEM(*certPath, *keyPath)
		if err != nil {
			fatal(err)
		}
		opts.Identity = id
	}

	if *ents != "" {
		b, err := os.ReadFile(*ents)
		if err != nil {
			fatal(err)
		}
		opts.Entitlements = b
	}

	for _, path := range flag.Args() {
		result, err := codesign.SignFile(path, opts)
		if err != nil {
			fatal(fmt.Errorf("%s: %w", path, err))
		}
		// At -v or higher, emit the richer Apple-style confirmation line.
		// At level 0, keep output minimal (just "signed").
		if verbosity >= codesign.VerbosityV1 {
			fmt.Printf("%s: signed %s [%s]\n", path, result.Format, result.Identifier)
		} else {
			fmt.Printf("%s: signed\n", path)
		}
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "codesigner:", err)
	os.Exit(1)
}