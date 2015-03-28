# Simple Session Capture
A simple capture program written for Linux that will listen on an interface and then put each session (ip, port, proto) into its own PCAP file.
The PCAP files are stored in a directory hash so you don't overload 1 directory with 1000s of files.


## Changelog
1.18.2013 - added filehashmap for file directory/structure hashing in an attempt to distribute pcaps over multiple directories
1.19.2013 - version 0.7.2 - added support for a specified output directory, and a chroot is done into the output directory
1.19.2013 - wrote a simple shell script to manage the pcap storage
3.27.2015 - finally releasing it/doing something with it
