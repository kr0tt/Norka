# Norka
Copying shellcode to existing RWX memory regions to avoid IoCs based on memory allocations and protections is a well-known technique, first mentioned (to my knowledge) by [namazso](https://twitter.com/namazso) [here](https://www.unknowncheats.me/forum/anti-cheat-bypass/286274-internal-detection-vectors-bypass.html) and later made more known with [Process Mockingjay](https://www.securityjoes.com/post/process-mockingjay-echoing-rwx-in-userland-to-achieve-code-execution).

Norka slightly adds to this by searching code caves within RWX memory regions that are large enough to house our shellcode to avoid crashing the target process or loading a DLL with RWX memory regions that might not be present on a host. Additionally, execution of the shellcode is achieved by inserting a trampoline to the thread pool worker factory start routine that will jump to our shellcode and execute it.

It should be noted that a limitation exists in the form of the size of the code cave. It is unlikely to locate a code cave large enough to store shellcode of a fully fledged C2 like Cobalt Strike/Havoc and the like. While playing around with this, I've tested two processes with code caves large enough to store basic payloads and reverse shells: OneDrive and Spotify, but more such processes can be found.
## Credits
- [namazso](https://twitter.com/namazso)
- [Process Mockingjay](https://www.securityjoes.com/post/process-mockingjay-echoing-rwx-in-userland-to-achieve-code-execution)
- [Uri3n's](https://github.com/Uri3n) [Thread-Pool-Injection-PoC](https://github.com/Uri3n/Thread-Pool-Injection-PoC)
- [This ired.team article](https://www.ired.team/offensive-security/defense-evasion/finding-all-rwx-protected-memory-regions)
