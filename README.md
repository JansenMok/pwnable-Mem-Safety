# Write-Up


## Question 1: Remus
### Main Idea
I utilized a `gets` vulnerability in order to continue writing into the stack past designated buffer. This allowed me to write into the location of memroy where the `rip` was stored. I then wrote the `SHELLCODE` into the address right after the `rip`, and then overwrote `rip` to point to the address of the `SHELLCODE`. This is because once the function returns, it will automatically move set the `eip` to `rip` and resume running the program. We can take advatange of this and make `eip` run our `SHELLCODE` instead of returning and continuing the program.
