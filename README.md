# Magic Control Technology (MCT) USB Display Adapter Reverse Engineering

Magic Control Technology Corporation (MCT, [website][mct]) is a Taiwanese
fabless semiconductor company that designs chips for use in computer peripherals
and multimedia equipment.

The targets of this reverse engineering effort are MCT's "Trigger 5" and
"Trigger VI" ("Trigger 6") USB-to-display adapters, the drivers for which only
support Windows and Mac OS. The goal of this project is to document the protocol
these chips use so a Linux driver can be written to support them and the display
adapters that use them.


## Quick start


### Software dependencies

* Python 3
* [PyUSB][pyusb]
* For parsing T6 firmware images:
  * [Kaitai Struct Compiler][ksc]
  * [Kaitai Struct Python Runtime][kspr]


### Procedure

1. Install dependencies.
2. Use `./test_t5.py` to replay some packets to the Trigger 5 dongle. This is
   work-in-progress research code and doesn't do much yet.


## Reverse engineering notes

See [Notes.md](doc/Notes.md).


[mct]: https://mct.com.tw/
[pyusb]: https://github.com/pyusb/pyusb
[ksc]: https://github.com/kaitai-io/kaitai_struct_compiler
[kspr]: https://github.com/kaitai-io/kaitai_struct_python_runtime
