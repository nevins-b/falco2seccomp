# falco2seccomp

This tool is designed to convert [Falco](http://www.sysdig.org/falco/) JSON logs to [Docker seccomp profiles](https://github.com/docker/docker/blob/master/docs/security/seccomp.md)

The Falco rule which this tool is designed to work with looks like:

```yaml
- rule: container_syscall
  desc: Capture syscalls for any docker container
  priority: WARNING
  condition: container.id != host and syscall.type exists
  output: "%container.id:%syscall.type"
```

This tool was first introduced in [Using-Falco-to-secure-Docker-containers](https://http206.com/2016/07/01/Using-Falco-to-secure-Docker-containers/)
