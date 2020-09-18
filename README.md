# PrefetchMute
This is a tool that allows you to prevent files being written by the Windows Prefetch service, filtering by filename. You can read more in the accompanying blog post [here](https://passthehashbrowns.github.io/muting-prefetch/).

Most of the code from this project was taken from [EvtMute by bats3c](https://github.com/bats3c/EvtMute) and tweaked for Prefetch.

## Usage
Inject PrefetchMute.dll into the Sysmain service through a method of your choosing. PrefetchMuteInjector is a C# program that can find the svchost.exe process running Sysmain and inject into it. The injector can also update the filter list over a named pipe.

Filtering is performed by a simple substring check. To entirely prevent Prefetch files from being written you could filter for ".pf", the Prefetch file extension, or "C" as Prefetch files are written to C:\Windows\Prefetch by default (keep in mind this can be changed).

## Considerations, limitations, and pitfalls
A few important things to note about my implementation of this. Most importantly, CreateFile calls may still be picked up through logging like Sysmon, but the file will not be created. This is something I may look into, but the current capability fits my use case. I have not found a way around this, if you do then please submit a pull request or hit me up on Twitter. 

Second, the filter check being performed is a simple check for a substring in the prefetch file name (which includes the entire path, like "C:\Windows\Prefetch\NET.EXE-hash". This means that if you add "net" to the filter list, it will also block "netstat". This was done on purpose to allow for blocking many programs with a single update, such as any C# tooling with "Sharp" in the name. You can avoid any collateral blockage by including the file extension, ie: "net.exe".

Finally, Prefetch is only one of several methods for tracking program execution in Windows. This won't stop other items, such as Shimcache or normal event logging, from taking place.

## Todo
Some housekeeping items I'll add in the near future:
* Remove items from filter list
* Obtain current items from filter list
* Add hash calculator for matching on filepath hashes
