# CVE-2022-42045
## Summary
  We discovered an Arbitrary code injection in Zemana amsdk.sys kernel-mode driver, a part of Zemana Antimalware SDK. The vulnerability allows to inject an arbitrary code into the one of the driver code sections and then to execute it with kernel-mode privileges (local privileges escalation from admin to kernel mode). This vulnerability could be used, for example, to disable Driver Signature Enforcement and then to install unsigned kernel-mode drivers.
## Details 
  The vulnerable function is placed at the offset 0xBF60 from the start of the .text section of amsdk.sys. This function invokes another one at the offset 0xD664. The function at the offset 0xD664 gets 4 arguments:
1. Target address: address of the function in .hook section with RWX access rights. In our case this argument points to the function at the offset 0x1D0 from the start of .hook sections
2. Source address: address of a source buffer with user controlled code
3. Some integer value. 128 in our case
4. Some address of a some function inside ntoskrnl.exe. This function is invoked just after invoking of the code from argument 2. BUT before it this argument value is increased by the length of a code from argument 2 minus 1. This length is calculated by the embedded to the driver lightweight disassembler. So, after the invoking of a code from argument 2 the control is transferred to the arg_4 + arg_2_length – 1.
   
IOCTL 0x80002044 calls the function at the offset 0xBF60 (.text section) and allows to fill the stub in .hook section by an arbitrary user controlled code. IOCTL 0x80002014 (read via SCSI) or IOCTL 0x80002018 (write via SCSI) transfers a control to this filled stub.
### Affected products
   At least Watchdog Anti-Malware 4.1.422 , Zemana AntiMalware 3.2.28. These products have the same vulnerable driver but signed with different certificates.
   
   Zemana AntiLogger v2.74.2.664 has the same vulnerability. Vulnerable drivers: zamguard64.sys, zam64.sys.
### Affected operating systems
  64-bit versions of Windows: from Windows 7 to Windows 11
## Mitigation
  Uninstall Zemana or Watchdog Antimalware products. Add driver signatures to blacklist.

![Result](https://github.com/ReCryptLLC/CVE-2022-42045/blob/main/PoC.png)
