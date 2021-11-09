# NEO3 Wireshark Dissector
This wireshark dissector is compatible with NEO [v3.0.3](https://github.com/neo-project/neo/releases/tag/v3.0.3). It supports all base payloads with just a few limitations (see below). Feel free to extend and PR!

![Alt text](./screenshot.png?raw=true "Sample")

## Installation
Place `neo3.lua` in the Wireshark plugin folder. See [their wiki](https://www.wireshark.org/docs/wsug_html_chunked/ChPluginFolders.html) for the location on your platform.
Requires Wireshark 3.0 or higher.

## Usage
The default port it will try to decode as NEO3 traffic is TCP port `10333`. If you're running your node on another port, 
i.e. `20333` is common for NEO's TestNetwork, then rigth click the stream, select `Decode As..` and choose `Neo3`.

## Limitations
* Cannot dissect compressed payloads. 
  
   Wireshark has not exposed its LZ4 library to their LUA environment and it is not possible load 3rd party libs. It has
   been an outstanding request for a long time. Our best bet is ask NEO to allow for compression negotiation such that
   it can be disabled, or to implement the dissector in C where it is possible to access the included LZ4 library. 

   If you're in control of the nodes you could build them from source and disable compression:
  * for neo-mamba [here](https://github.com/CityOfZion/neo-mamba/blob/598f2b6e522daf80e1adbe9b50680c7234e2fa14/neo3/network/message.py#L83) 
  * for neo-cli [here](https://github.com/neo-project/neo/blob/d092510d0b416f30d5dca7be9913193443bebb96/src/neo/Network/P2P/Message.cs#L69)
  * for neo-go [here](https://github.com/nspcc-dev/neo-go/blob/173bf0be621a0d2fde6a1c9fa1fb13b4fb84ea7b/pkg/network/message.go#L188)

* The `AddrPayload` and `ExtensiblePayload` are not supported. 
  
  Note: no `ExtensiblePayload` support implies no support for [consensus payloads](https://github.com/neo-project/neo-modules/blob/f8ce79cfb5e2d68ef6ca6d1dfbccd8d4fd24fa3b/src/DBFTPlugin/Consensus/ConsensusContext.MakePayload.cs). 