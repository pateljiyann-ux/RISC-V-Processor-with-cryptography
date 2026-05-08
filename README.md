# RISC-V-Processor-with-cryptography
This project presents the design and implementation of a single-cycle RISC-V processor integrated with AES-128 cryptographic functionality. The objective is to enhance processor capability by enabling hardware-accelerated encryption , making it suitable for secure embedded and communication systems.
#  RISC-V Processor with AES Cryptographic Accelerator

This project implements a **single-cycle RISC-V processor** integrated with a **hardware AES-128 encryption engine**. The design combines general-purpose computation with cryptographic acceleration, making it suitable for secure embedded systems and hardware security applications.

---

##  Project Overview

The processor is based on the **RV32I instruction set** and enhanced with a **custom AES instruction extension**. When triggered, the processor offloads cryptographic operations to a dedicated AES hardware block, significantly improving performance over software-based encryption.

---

##  Key Features

###  RISC-V Core
- Single-cycle architecture
- Supports standard RV32I instructions:
  - Arithmetic & Logic
  - Load/Store
  - Branch & Jump
- Modular design (ALU, Control Unit, Register File, etc.)

###  AES-128 Hardware Engine
- Fully implemented AES pipeline:
  - SubBytes (S-Box lookup)
  - ShiftRows
  - MixColumns
  - AddRoundKey
  - Key Expansion (10 rounds)

- Supports multiple AES operations:
  - `aessub`
  - `aesshift`
  - `aesmix`
  - `aeskey`
  - `aesenc` (full encryption)

###  Custom Instruction Support
- Dedicated opcode (`0001011`) enables AES execution
- Controlled using `AES_EN` signal in control unit
- AES result integrated into processor write-back stage

---

##  Architecture

###  Processor Flow
Instruction Fetch → Decode → Execute → Memory → Writeback

###  AES Integration
The AES module is tightly coupled with the processor datapath:
- Register values are converted into 128-bit AES input
- AES engine performs selected operation
- Result is written back into the register file

---

## 📂 Project Structure

```bash
├── risc.v
├── program.hex
├── testbench.v
├── README.md
