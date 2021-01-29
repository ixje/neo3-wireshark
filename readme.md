# NEO3 Wireshark Dissector
This wireshark dissector is compatible with Preview 4. Not all payloads can be fully dissected, but at least payloads will be named. Feel free to extend and PR!

![Alt text](./screenshot.png?raw=true "Sample")

## Installation
Place `neo3.lua` in the Wireshark plugin folder. See [their wiki](https://www.wireshark.org/docs/wsug_html_chunked/ChPluginFolders.html) for the location on your platform.

## Missing features
* Cannot dissect compressed payloads. 
  
   Wireshark has not exposed its LZ4 library to their LUA environment and it is not possible load 3rd party libs. It has
   been an outstanding request for a long time. Our best bet is waiting for NEO3 to finalize and then implement the 
   dissector in C where it is possible to access the included LZ4 library.

* Block payloads are only partially dissected

* Transaction and consensus related payloads are not dissected.