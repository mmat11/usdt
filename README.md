# usdt

[![Go Report Card](https://goreportcard.com/badge/github.com/mmat11/usdt)](https://goreportcard.com/report/github.com/mmat11/usdt)
[![Go Reference](https://pkg.go.dev/badge/github.com/mmat11/usdt)](https://pkg.go.dev/github.com/mmat11/usdt)
[![CI](https://github.com/mmat11/usdt/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/mmat11/usdt/actions/workflows/ci.yml)

## Introduction

`usdt` is a Go library for linking `cilium/ebpf`'s `Program` to userspace statically defined tracepoints.

## Getting started

TODO: examples

### Testing

Install dev dependencies

- clang 12
- `apt install systemtap-sdt-dev` (Debian/Ubuntu), `dnf install systemtap-sdt-devel` (Fedora)
- `pip install stapsdt black isort`
- https://github.com/linux-usdt/libstapsdt

```
make -C testdata
go test -exec sudo -v ./
```

## More links and documentation

* https://lwn.net/Articles/753601/
* https://sourceware.org/systemtap/wiki/UserSpaceProbeImplementation
* https://bpf.sh/usdt-report-doc/index.html
* https://bpf.sh/production-breakpoints-doc/index.html
* https://medium.com/sthima-insights/we-just-got-a-new-super-power-runtime-usdt-comes-to-linux-814dc47e909f
* https://github.com/goldshtn/linux-tracing-workshop/blob/master/bpf-usdt.md

## License

The code and docs are released under the [MIT](LICENSE).
