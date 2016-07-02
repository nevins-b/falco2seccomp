package config

import (
	"io/ioutil"
	"log"

	"github.com/deckarep/golang-set"

	"gopkg.in/yaml.v2"
)

type Config struct {
	DefaultAction string   `yaml:"defaultAction"`
	Architectures []string `yaml:"architectures"`
	DefaultDeny   []string `yaml:"defaultDeny"`
	DenySet       mapset.Set
	ContainerID   string
	RuleName      string
}

func LoadConfig(path, containerID, ruleName *string) *Config {

	c := Config{
		ContainerID: *containerID,
		RuleName:    *ruleName,
		DenySet:     mapset.NewSet(),
	}
	data, err := ioutil.ReadFile(*path)
	if err != nil {
		log.Fatal(err)
	}

	err = yaml.Unmarshal(data, &c)
	if err != nil {
		log.Fatal(err)
	}
	for _, syscall := range c.DefaultDeny {
		c.DenySet.Add(syscall)
	}
	return &c
}
