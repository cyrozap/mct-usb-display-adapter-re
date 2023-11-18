# Packet captures

This directory contains packet captures of the USB communications between some
MCT Trigger 6 devices and their proprietary driver for Windows. The [Wireshark
dissector plugin][plugin] can be used to analyze these packet captures.

Capture files are named according to the following pattern:

```
trace-<device type>-<date and time the capture was saved>-<operating system>-<brief description of actions performed during the packet capture>.pcapng.gz
```


[plugin]: ../wireshark
