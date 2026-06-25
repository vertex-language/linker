package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/vertex-language/linker/macho/codesign"
)

func main() {
	var (
		sign     = flag.String("sign", "", `signing identity; "-" for ad-hoc, or a name/path for a cert`)
		certPath = flag.String("cert", "", "PEM certificate (+chain) for production signing")
		keyPath  = flag.String("key", "", "PEM private key for production signing")
		ident    = flag.String("identifier", "", "explicit code-signing identifier")
		team     = flag.String("team-identifier", "", "team identifier")
		ents     = flag.String("entitlements", "", "path to entitlements plist (XML)")
		force    = flag.Bool("f", false, "replace any existing signature")
		hardened = flag.Bool("o", false, "enable hardened runtime (CS_RUNTIME)")
	)
	flag.Parse()

	if *sign == "" || flag.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: codesign --sign - [-f] [-o] [--identifier id] <binary>")
		os.Exit(2)
	}

	opts := codesign.Options{
		Identifier: *ident,
		TeamID:     *team,
		Force:      *force,
		Hardened:   *hardened,
	}

	if *sign != "-" { // production: load identity
		if *certPath == "" || *keyPath == "" {
			fmt.Fprintln(os.Stderr, "production signing needs --cert and --key (PEM)")
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
		if err := codesign.SignFile(path, opts); err != nil {
			fatal(fmt.Errorf("%s: %w", path, err))
		}
		fmt.Printf("%s: signed\n", path)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "codesign:", err)
	os.Exit(1)
}