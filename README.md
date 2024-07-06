# Norka
Copying shellcode to existing RWX memory pages or RWX sections to avoid IOCs based on memory allocations and protections is a well-known technique, first mentioned (to my knowledge) by [namazso](https://twitter.com/namazso) [here](https://www.unknowncheats.me/forum/anti-cheat-bypass/286274-internal-detection-vectors-bypass.html) and later made more known with [Process Mockingjay](https://www.securityjoes.com/post/process-mockingjay-echoing-rwx-in-userland-to-achieve-code-execution).

Unlike the previous techniques that target RWX sections, norka searches code caves within RWX memory pages that are large enough to house our shellcode and copies the shellcode there to avoid crashing the target process. Additionally, execution of the shellcode is achieved by inserting a trampoline to the thread pool worker factory start routine that will jump to our shellcode and execute it.

It should be noted that a limitation exists in the form of the size of the code cave. It is unlikely to locate a code cave large enough to store shellcode of a fully fledged C2 like Cobalt Strike/Havoc/Sliver and the like. While playing around with this, I've tested two processes with code caves large enough to store basic payloads and reverse shells: OneDrive and Spotify, but more such processes can be found.

TL;DR - nothing new, code caves are cool.
## Credits
- [namazso](https://twitter.com/namazso)
- [Process Mockingjay](https://www.securityjoes.com/post/process-mockingjay-echoing-rwx-in-userland-to-achieve-code-execution)
- [Uri3n's](https://github.com/Uri3n) [Thread-Pool-Injection-PoC](https://github.com/Uri3n/Thread-Pool-Injection-PoC)
- [This ired.team article](https://www.ired.team/offensive-security/defense-evasion/finding-all-rwx-protected-memory-regions)
