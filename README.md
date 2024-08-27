# elf_disassembler
Disassemble x86-64 ELF files using Capstone

# Install
```bash
sudo apt update
sudo apt install -y build-essential libelf-dev libcapstone-dev libmmap-dev libm math-dev libm-dev
make
```

# Run
```bash
./elf_disassembler <executable>
```