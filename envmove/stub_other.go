//go:build !linux

package main

import "fmt"

// The engine runs on Linux. This lets the tests of its portable parts build elsewhere.
func main() { fmt.Println("envmove runs on Linux") }
