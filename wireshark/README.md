# Wireshark dissector plugin

A dissector plugin for Wireshark that can decode the MCT Trigger 6 protocol.


## How to use

1. `make`
2. `install -Dm755 mct_trigger.so ~/.local/lib/wireshark/plugins/4.0/epan/mct_trigger.so`
3. Start Wireshark and open a USB capture file containing Trigger 6 protocol data.


## License

[GNU General Public License, version 2 or later][license].


[license]: COPYING.txt
