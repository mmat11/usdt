import stapsdt

provider = stapsdt.Provider("X")
probe = provider.add_probe("Y", stapsdt.ArgTypes.uint64)
provider.load()


if __name__ == "__main__":
    while True:
        probe.fire("hello world")
