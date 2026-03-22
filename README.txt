dl
fast windows downloader in pure c

INSTALL
=======

download dl-setup.exe from the latest release and run it

that is the main install path


after install, open a new shell and use:

    dl

BENCHMARK
=========

real run
not synthetic benchmark bullshit

    .\dl.exe https://download.freebsd.org/releases/amd64/amd64/ISO-IMAGES/15.0/FreeBSD-15.0-RELEASE-amd64-disc1.iso
    [FreeBSD-15.0-RELEASE-amd64-disc1.iso]  14.6% | 189.5 MB / 1.3 GB | 60.2 MB/s | ETA 18s | [32 segments]

on a good mirror this thing can absolutely clown a regular browser download and beat the shit out of aria2c too

if the speed is bad, one of these is true:

    the downloader sucks
    the mirror sucks
    your route sucks

usually it is the mirror

BUILD
=====

if you want to build it yourself, open a visual studio x64 developer shell and run this:

    cl.exe /O2 /Oi /GL /GS- /fp:fast /arch:AVX2 /DNDEBUG /DUNICODE /D_UNICODE ^
        /Fe:dl.exe dl.c ^
        /link /LTCG /OPT:REF /OPT:ICF /SUBSYSTEM:CONSOLE ^
        ws2_32.lib secur32.lib crypt32.lib kernel32.lib ntdll.lib advapi32.lib user32.lib

if you use clang-cl, point it at the same msvc + windows sdk setup and it should stop whining

USAGE
=====

    dl <url>
    dl <url> -o <filename>
    dl <url> -j <num>
    dl <url> -b <bytes>
    dl <url> --no-resume
    dl <url> --insecure
    dl <url> -v
    dl <url> -q
    dl <url> --limit-rate <speed>
    dl --help
    dl --version

EXAMPLES
========

    dl https://fastly.mirror.pkgbuild.com/iso/2026.03.01/archlinux-2026.03.01-x86_64.iso
    dl https://example.com/file.iso -o arch.iso
    dl https://example.com/file.iso -j 64
    dl https://example.com/file.iso --limit-rate 200M

DEFAULTS
========

buffer: 4 MiB
auto segments: 4 / 8 / 16 / 24 / 48 / 64
retries: 10 per segment
resume state file: <output>.dl.state

WHAT IT DOES
============

raw http/1.1 over winsock2
https through schannel
redirects
ranged downloads
resume support
direct writes into the destination file
rate limiting
quiet mode if you hate seeing text move around

WHAT IT DOES NOT DO
===================

linux
mac
bsd yet
magic
compressed http bodies yet

NOTES
=====

this is windows-only

if the server ignores range, dl drops to one connection and deals with it

if you want to slam a fat pipe, try:

    -j 64

if 64 connections still does not move the needle, stop yelling at the downloader and pick a less cursed mirror

LICENSE
=======

bsd 2-clause
see LICENSE
