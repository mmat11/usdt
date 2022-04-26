# usdt

[![Go Report Card](https://goreportcard.com/badge/github.com/mmat11/usdt)](https://goreportcard.com/report/github.com/mmat11/usdt)
[![Go Reference](https://pkg.go.dev/badge/github.com/mmat11/usdt)](https://pkg.go.dev/github.com/mmat11/usdt)
[![CI](https://github.com/mmat11/usdt/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/mmat11/usdt/actions/workflows/ci.yml)

## Introduction

`usdt` is a Go package for linking `cilium/ebpf`'s `Program` to userspace statically defined tracepoints.

## Getting started

You can find an example in the examples folder.

To try it, start a python process:

```
(venv) ➜  cpython git:(main) ✗ python
Python 3.10.4 (main, Mar 25 2022, 00:00:00) [GCC 11.2.1 20220127 (Red Hat 11.2.1-9)] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import os
>>> os.getpid()
373829
```

Then run the Go process and observe `function__entry` tracepoint events:

```
go run -exec sudo ./ -pid 373829

/usr/lib64/python3.10/random.py:366 -> randint()
/usr/lib64/python3.10/random.py:292 -> randrange()
/usr/lib64/python3.10/random.py:239 -> _randbelow_with_getrandbits()
```

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
