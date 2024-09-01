# bpf_reuseport
bpf_reuseport

### Build and Run 
```bash
git clone https://github.com/txuna/bpf_reuseport.git
cd bpf_reuseport
go get github.com/cilium/ebpf/cmd/bpf2go
go generate
go build
sudo ./ebpf_reuseport
```

***Other Shell***
```bash
nc localhost 9988
```