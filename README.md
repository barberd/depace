# depace
Code to remove PACE anti-piracy on select early 68k Macintosh abandonware

In the mid-80s, software publishers sought solutions to prevent copying of software to new floppies. PACE Anti-Piracy, Inc offered a solution for the early Macintoshes. PACE created self-modifying code that would decrypt and execute anti-piracy routines on the fly. These routines would check the floppy disk for the existence of a bad block. If the block was not bad, the software would refuse to run as likely someone had copied the floppy.

Since the floppy-checking routines were encrypted, it was more difficult to bypass the anti-piracy check. Additionally, a few applications (MacWars and Seven Cities of Gold), the entire application was encrypted, not just the anti-piracy code. The anti-piracy routines also include checks to make sure debugging software is not in use, even going as far as checking how much time has passed between different stages of decryption and rebooting if it detects anything unusual.

However, as the original disks are failing at 35+ years old and this software is often accessed via emulators today, these anti-piracy routines make the software unusable.

These scripts decrypt and patch these applications so they can be used again today with new floppies and on emulators.

Please note these scripts are written to modify the application stored in MacBinary format, and expect the resource fork to be located at 0x80. If you are operating directly on resource fork files, you may need to modify the code to remove the "+0x80" directives in the seek() calls.

The decrypt/ dir contains the scripts that decrypt the application binaries, so the application code and anti-piracy code is available for inspection in forensic tools/disassemblers/etc. Note that decryption alone is not enough to make the applications usable, as the anti-piracy checks are still in place.

The patch/ dir contains scripts that modify the application binaries to bypass the anti-piracy routines. 

For MacWars and Seven Cities of Gold, the entire application is encrypted and must be decrypted. For these, run the decryption scripts, then run the patch scripts.

The other applications only have the anti-piracy routines encrypted, so one can just run the patch scripts without first decrypting, as the patch will bypass the encrypted routines altogether. The decryption scripts for these applications are more of interest for researchers and computer archeologists.


