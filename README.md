SYSTEMSGX
=======================================
S-OpenSGX, built on top of OpenSGX and QEMU's system emulation mode, 
aims to tackle several limitations of OpenSGX (scheduling, 
multi-threading, SGX paging, etc).
S-OpenSGX consists of SystemSGX and SGX-Guest.
SystemSGX is S-OpenSGX's System SGX Emulator which runs in a host machine.
With system emulation, not only SGX-enabled CPU and MMU but also peripherals 
can be freely modified in SystemSGX.

Changho Choi <zpzigi@kaist.ac.kr>


Environments & Prerequisites
----------------------------
- Host OS: Ubuntu 14.04
- Guest OS: Ubuntu 12.04 (will be tested with 14.04 later)
- Requisite
$ apt-get build-dep qemu
$ apt-get install libelf-dev

- Building and Usage
(Let's assume that you put systemsgx in your (TOP) directory)
  1. Run `configure-sys` and `make` in (TOP)/systemsgx/qemu/ directory for building.
      It will create qemu-system-x86\_64 binary in (TOP)/systemsgx/qemu/x86\_64-softmmu

  2. Please create your QEMU ubuntuimage file and put it in (TOP)/systemsgx/qemu/x86\_64-softmmu directory.

  3. Run `./qemu-system-x86\_64 -hda ubuntuimage -m 4096 1 > dbg-test.txt 2 > err-test.txt -vga vmware -net user,hostfwd=tcp::10022-:22 -net nic` in (TOP)/systemsgx/qemu/x86\_64-softmmu directory.
(Please make sure that device.key file is in the ./conf directory of the current working directory where qemu-system-x86\_64 is executed)


Acknowledgment
----------------------------
We would like to thank Taesoo Kim at Georgia Tech and Zhiqiang Lin at UT Dallas, 
for their insightful comments and suggestions.
