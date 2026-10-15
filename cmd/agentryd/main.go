// agentryd is the Agentry server binary: a modular monolith whose role is
// chosen on the command line (api | git | worker | all). Everything it does
// lives in pkg/extension, which a build with extensions calls with them;
// the core build calls it with none.
package main

import "github.com/blaktron/agentry/pkg/extension"

func main() { extension.Main() }
