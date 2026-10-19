package main

import (
	"strings"
	"testing"
)

func TestClassify(t *testing.T) {
	bsdHead := "Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:\n" +
		"1. Redistributions of source code must retain the above copyright notice.\n" +
		"2. Redistributions in binary form must reproduce the above copyright notice.\n"
	cases := []struct {
		name, text, want string
	}{
		{"apache", "                                 Apache License\n                           Version 2.0, January 2004", "Apache-2.0"},
		{"mpl", "Mozilla Public License Version 2.0\n==================================", "MPL-2.0"},
		{"mit", "Permission is hereby granted, free of charge, to any person obtaining a copy\n... THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY", "MIT"},
		{"isc", "Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted", "ISC"},
		{"bsd2", bsdHead, "BSD-2-Clause"},
		{"bsd3", bsdHead + "3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse", "BSD-3-Clause"},
		{"unknown", "All rights reserved.", ""},
	}
	for _, c := range cases {
		if got := classify(c.text); got != c.want {
			t.Errorf("%s: classify = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestLicenceNames(t *testing.T) {
	for _, name := range []string{"LICENSE", "LICENSE.txt", "LICENSE.md", "COPYING", "LICENSE-MIT", "UNLICENSE"} {
		if !licenceName.MatchString(name) {
			t.Errorf("%s should be read as a licence file", name)
		}
	}
	for _, name := range []string{"license.go", "licenser.go", "license_test.go"} {
		if licenceName.MatchString(name) {
			t.Errorf("%s is source, not a licence file", name)
		}
	}
	if !noticeName.MatchString("NOTICE.txt") || noticeName.MatchString("notice.go") {
		t.Error("notice file names are matched wrongly")
	}
}

func TestSourceNoteNamesUpstreamForCopyleftModules(t *testing.T) {
	m := &module{path: "github.com/riverqueue/river/riverdriver", version: "v1.2.3",
		licences: []licenceFile{{spdx: "MPL-2.0"}}}
	notes := m.sourceNote()
	if len(notes) != 1 || !strings.Contains(notes[0], "https://github.com/riverqueue/river at version v1.2.3") {
		t.Fatalf("source note = %q", notes)
	}
	if (&module{path: "example.com/x", licences: []licenceFile{{spdx: "MIT"}}}).sourceNote() != nil {
		t.Error("an MIT module needs no source note")
	}
}
