## Install

### LIBBPF

```
git submodule update --init
cd libbpf/src
make
cd -
```
```bash
make
# bpftool prog load keylog.bpf.o /sys/fs/bpf/keylog autoattach

```

```bash
# Print BPF kernel log
bpftool prog tracelog
```
