uefi-simpleを流用してU-Bootに含まれるSHA,RSAのベンチマークをqemu-system-aarch64上で実行。

    $ git clone <this repository>
    $ cd uefi-bench-uboot
    $ git submodule init
    $ git submodule update
    $ make ARCH=aa64 CROSS_COMPILE=aarch64-linux-gnu-
    $ qemu-system-aarch64 -m 512 -cpu cortex-a57 -machine virt -bios QEMU_EFI.fd -serial stdio -hda fat:rw:.
    < Enter EFI Internal Shell >
    Shell> main
    
    *** UEFI Simple ***
    
    UEFI v2.70 (EDK II, 0x00010000)
    QEMU QEMU Virtual Machine
    EFI Development Kit II / OVMF 0.0.0
    Secure Boot status: Disabled
    ctr_freq: 62500000
    
    benchmark_main
    sha1 out: A9 99 3E 36 47 06 81 6A BA 3E 25 71 78 50 C2 6C 9C D0 D8 9D
    sha1 check: OK
    sha1 elaps: 3631280 (58100usec)
    --- Minimum: 3631280 (58100usec) ---
    sha256 out: BA 78 16 BF 8F 01 CF EA 41 41 40 DE 5D AE 22 23 B0 03 61 A3 96 17 7A 9C B4 10 FF 61 F2 00 15 AD
    sha256 check: OK
    sha256 elaps: 311685 (4986usec)
    --- Minimum: 311685 (4986usec) ---
    rsa2048 out: 00 01 FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF     FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF 00 30 21 30 09 06 05 2B 0E 03 02 1A 05 00 04 14 19 1C B1 21 51 4F EF 57 91 A9 58 2E 9B 23 BC 0E 71 88 13 2C
    rsa2048 check: OK
    rsa2048 elaps: 524017 (8384usec)
    --- Minimum: 524017 (8384usec) ---
    
    Press any key to exit.

トラブルシューティング

- `git submodule update`で`fatal: unable to connect to git.code.sf.net:`エラーが発生する場合は[https://wiki.osdev.org/GNU-EFI](https://wiki.osdev.org/GNU-EFI)の[GNU-EFI](https://sourceforge.net/projects/gnu-efi/files/)のリンクからソースコードをダウンロードして`uefi-bench-uboot/gnu-efi`に配置すればよい。


UEFI:SIMPLE - EFI development made easy
=======================================

A simple UEFI "Hello World!" style application that can:
* be compiled on Windows or Linux, using Visual Studio 2019, MinGW or gcc.
* be compiled for x86_32, x86_64, ARM or ARM64/AARCH64 targets
* be tested on the fly, through a [QEMU](https://www.qemu.org/) + 
 [OVMF](https://github.com/tianocore/tianocore.github.io/wiki/OVMF) or
 [QEMU_EFI](http://snapshots.linaro.org/components/kernel/leg-virt-tianocore-edk2-upstream/latest/)
 virtual machine.

## Prerequisites

* [Visual Studio 2019](https://www.visualstudio.com/vs/community/) or gcc/make
* [QEMU](http://www.qemu.org) __v2.7 or later__
  (NB: You can find QEMU Windows binaries [here](https://qemu.weilnetz.de/w64/))
* git
* wget, unzip, if not using Visual Studio

## Sub-Module initialization

For convenience, the project relies on the gnu-efi library, so you need to initialize the git
submodule either through git commandline with:
```
git submodule init
git submodule update
```
Or, if using a UI client (such as TortoiseGit) by selecting _Submodule Update_ in the context menu.

## Compilation and testing

If using Visual Studio, just press `F5` to have the application compiled and
launched in the QEMU emulator.

If using MinGW or Linux, issue the following from a command prompt:

`make`

If needed you can also add `ARCH=<arch>` and `CROSS_COMPILE=<tuple>`, e.g.:

* `make ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf-`
* `make ARCH=aa64 CROSS_COMPILE=aarch64-linux-gnu-`

where `<arch>` can be `x64`, `ia32`, `arm` or `aa64`.

You can also add `qemu` as your `make` target to run the application under QEMU,
in which case a relevant UEFI firmware (OVMF for x86 or QEMU_EFI for Arm) will
be automatically downloaded to run your application against it.

## Visual Studio 2019 and ARM/ARM64 support

Please be mindful that, to enable ARM or ARM64 compilation support in Visual Studio
2019, you __MUST__ go to the _Individual components_ screen in the setup application
and select the ARM/ARM64 build tools there, as they do __NOT__ appear in the default
_Workloads_ screen:

![VS2019 Individual Components](https://files.akeo.ie/pics/VS2019_Individual_Components.png)
