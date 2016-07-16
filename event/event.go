package event

import (
	"bufio"
	"encoding/json"
	"log"
	"os"
	"regexp"

	"github.com/nevins-b/falco2seccomp/config"
	"github.com/nevins-b/falco2seccomp/seccomp"
)

type EventParser struct {
	re     *regexp.Regexp
	config *config.Config
}

type Event struct {
	Output      string
	Priority    string
	Rule        string
	ContainerID string
	Syscall     string
}

func NewEventParser(config *config.Config) *EventParser {
	return &EventParser{
		// Regex is ugly, I'd love a better solution for this.
		re:     regexp.MustCompile(".*?((?:[a-z0-9]*)):((?:[a-z\\_]+))"),
		config: config,
	}
}

func (parser *EventParser) newEvent(data []byte) *Event {
	e := &Event{}
	err := json.Unmarshal(data, &e)
	if err != nil {
		return nil
	}
	if e.Rule != parser.config.RuleName {
		return nil
	}
	matches := parser.re.FindStringSubmatch(e.Output)
	if len(matches) == 0 {
		return nil
	}
	e.ContainerID = matches[1]
	e.Syscall = matches[2]

	if parser.config.DenySet.Contains(e.Syscall) {
		return nil
	}
	if e.ContainerID != parser.config.ContainerID {
		return nil
	}
	return e
}

func (parse *EventParser) ParseLog(eventLog *string) []byte {
	p := seccomp.NewProfile(parse.config)

	file, err := os.Open(*eventLog)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		e := parse.newEvent(scanner.Bytes())
		if e != nil {
			p.AllowSyscall(e.Syscall)
		}
	}
	profile, err := p.JSON()
	if err != nil {
		return nil
	}
	return profile
}
