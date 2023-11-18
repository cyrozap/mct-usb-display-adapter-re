# Wireshark dissector plugin

A dissector plugin for Wireshark that can decode the MCT Trigger 5 and Trigger 6
protocols.


## How to use

1. Build the plugin by running `make`.
2. Install the plugin for the current user by running `make install`.
3. Start Wireshark and open a USB capture file containing Trigger 5 or Trigger 6
   protocol data. Sample capture files can be found [here][captures].


## License

[GNU General Public License, version 2 or later][license].


[captures]: ../captures
[license]: COPYING.txt
