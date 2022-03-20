package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/danillouz/tdr/internal/dns"
	"github.com/danillouz/tdr/internal/resolver"
)

func main() {
	flag.Parse()

	name := flag.Arg(0)
	qt := dns.TypeA

	answer, err := resolver.Resolve(name, qt)
	if err != nil {
		log.Fatalf(
			"failed to resolve %s record(s) for name %s: %v",
			qt, name, err,
		)
	}

	fmt.Println("answer:", answer)
}
