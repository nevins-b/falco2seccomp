package seccomp

import (
	"encoding/json"
	"log"

	"github.com/deckarep/golang-set"
	"github.com/nevins-b/falco2seccomp/config"
)

type Profile struct {
	DefaultAction string    `json:"defaultAction"`
	Architectures []string  `json:"architectures"`
	Syscalls      []Syscall `json:"syscalls"`
	syscallSet    mapset.Set
}

type Syscall struct {
	Name   string   `json:"name"`
	Action string   `json:"action"`
	Args   []string `json:"args"`
}

func NewProfile(config *config.Config) *Profile {
	p := &Profile{
		DefaultAction: config.DefaultAction,
		Architectures: config.Architectures,
		syscallSet:    mapset.NewSet(),
	}

	return p
}

func (p *Profile) AllowSyscall(syscall string) {
	if p.syscallSet.Add(syscall) {
		s := Syscall{
			Name:   syscall,
			Action: "SCMP_ACT_ALLOW",
			Args:   []string{},
		}

		p.Syscalls = append(p.Syscalls, s)
	}
}

func (p *Profile) JSON() ([]byte, error) {
	if p.syscallSet.Cardinality() == 0 {
		p.Syscalls = []Syscall{}
	}
	log.Printf("Creating profile with %d syscalls allowed", p.syscallSet.Cardinality())
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return nil, err
	}
	return b, nil
}
