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
~~~~~~{.sh}
Ubuntu
$ apt-get build-dep qemu
$ apt-get install libelf-dev

- Compilation
Let's assume you installed systemsgx in ~/ (e.g., /home/changho/systemsgx/)
in ~/systemsgx/qemu/ please run 'configure-sys' and then 'make'
It will create qemu-system-x86\_64 binary in ~/systemsgx/qemu/x86\_64-softmmu

- Guest Image Creation
In ~/systemsgx/qemu/x86\_64-softmmu,
Please create or put your QEMU ubuntuimage file (You need enough space to recomiple your linux kernel. My image size is 26GB for your reference.)

- Run
In ~/systemsgx/qemu/x86\_64-softmmu,
Run ./qemu-system-x86\_64 -hda ubuntuimage -m 4096 1 > dbg-test.txt 2 > err-test.txt -vga vmware -net user,hostfwd=tcp::10022-:22 -net nic
(Please make sure that device.key file is in the ./conf directory of the current working directory where qemu-system-x86\_64 is executed)


Acknowledgment
----------------------------
We would like to thank Taesoo Kim at Georgia Tech and Zhiqiang Lin at UT Dallas, 
for their insightful comments and suggestions.
