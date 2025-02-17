# Write-Up


## Question 1: Remus
### Main Idea
I utilized a `gets` vulnerability in order to continue writing into the stack past designated buffer. This allowed me to write into the location of memroy where the `rip` was stored. I then wrote the `SHELLCODE` into the address right after the `rip`, and then overwrote `rip` to point to the address of the `SHELLCODE`. This is because once the function returns, it will automatically move set the `eip` to `rip` and resume running the program. We can take advatange of this and make `eip` run our `SHELLCODE` instead of returning and continuing the program.


## Question 2: Spica
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
The first `fread` would happily write `0xff` into `size`, which would then pass the `if` check due to it comparing `int8_t` type against `128`. Then after that, the second `fread` function call will treat `size` like a `size_t` (unsigned int), and now I can write past where I am not supposed to. After gaining access to the area in memory outside of the file limit, all I needed to do was find where the return address was stored, which would inevitably be executed once the function returned. Using GDB, I found the address of the `rip` and subtracted it from the address of the beginning of `msg`. The address of `rip` was `148` bytes away from the start of `msg`, so I filled in garbage for `148` bytes till the location of `rip`, then overwrote `rip` to be another address just `4` bytes ahead, and then placed the `SHELLCODE` right there, and boom. Exploited.
