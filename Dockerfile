FROM rustlang/rust:nightly

# Install prerequisites for eBPF and testing
RUN apt-get update && apt-get install -y \
    clang \
    llvm \
    libelf-dev \
    iproute2 \
    iputils-ping \
    tcpdump \
    hping3 \
    nmap \
    && rm -rf /var/lib/apt/lists/*

# Add rust-src for kernel ebpf compilation 
# and install bpf-linker
RUN rustup component add rust-src
RUN cargo install bpf-linker cargo-deb

WORKDIR /app
COPY . .

# Compile the kernel eBPF program
RUN cd firewallx-ebpf && cargo +nightly build --release -Z build-std=core --target bpfel-unknown-none

# Compile the userspace firewall
RUN cargo build --release --bin firewallx
RUN cd firewallx && cargo deb --no-build

CMD ["./target/release/firewallx"]
