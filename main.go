package main

import (
	"flag"
	"fmt"
	"io/ioutil"

	"github.com/nevinsb/falco2seccomp/config"
	"github.com/nevinsb/falco2seccomp/event"
)

func main() {

	eventLog := flag.String("log", "", "Falco event log file path, event must be in json format")
	configPath := flag.String("config", "config.yml", "Path to configuration")
	containerID := flag.String("container-id", "", "ID of container")
	ruleName := flag.String("rule-name", "container_syscall", "The name of the Falco rule")
	outFile := flag.String("out", "", "File to write profile to, stdout if not specified")

	flag.Parse()

	c := config.LoadConfig(configPath, containerID, ruleName)
	eP := event.NewEventParser(c)
	js := eP.ParseLog(eventLog)
	if *outFile != "" {
		ioutil.WriteFile(*outFile, js, 0600)
	} else {
		fmt.Println(string(js))
	}
}
