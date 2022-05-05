meta:
  id: mct_t6img
  file-extension: t6img
  endian: le
seq:
  - id: magic
    contents: "IMG_"
  - id: len
    type: u4
  - id: crc_maybe
    type: u4
  - id: unk2
    type: u4
  - id: unk3
    type: u4
  - id: image_code_version
    type: u4
  - id: firmware
    type: firmware
  - id: configs
    type: config_ptr
    repeat: expr
    repeat-expr: 12
  - id: project_code
    type: strz
    size: 16
    encoding: ASCII
  - id: unk5
    type: u4
types:
  firmware:
    seq:
      - id: offset
        type: u4
      - id: len
        type: u4
    instances:
      data:
        pos: offset
        size: len
  config_ptr:
    seq:
      - id: offset
        type: u4
    instances:
      config:
        pos: offset
        type: config
        if: 'offset != 0'
  config:
    seq:
      - id: type
        size: 4
        type: str
        encoding: "ASCII"
      - id: len
        type: u4
      - id: unk
        type: u4
      - id: data
        size: len - 12
        type:
          switch-on: type
          cases:
            '"UHAL"': uhal
            '"DISP"': disp
            '"AUD_"': aud
            '"GPIO"': gpio
  uhal:
    seq:
      - id: unk0
        type: u2
      - id: unk1
        type: u2
      - id: binary_object_store_start
        type: u2
      - id: unk3
        type: u2
      - id: manufacturer_start
        type: u2
      - id: product_start
        type: u2
    instances:
      device_usb2:
        pos: 0x2c
        type: descriptor
      device_usb3:
        pos: 0x40
        type: descriptor
      unk0_inst:
        pos: unk0 - 12
        type: descriptor
      unk1_inst:
        pos: unk1 - 12
        type: descriptor
      binary_object_store:
        pos: binary_object_store_start - 12
        type: binary_object_store
      unk3_inst:
        pos: unk3 - 12
        type: descriptor
      manufacturer:
        pos: manufacturer_start - 12
        type: descriptor
      product:
        pos: product_start - 12
        type: descriptor
    types:
      binary_object_store:
        seq:
          - id: b_length
            type: u1
          - id: b_descriptor_type
            type: u1
          - id: w_total_length
            type: u2
          - id: b_num_device_caps
            type: u1
      descriptor:
        seq:
          - id: b_length
            type: u1
          - id: b_descriptor_type
            type: u1
            enum: type
          - id: data
            size: b_length - 2
            type:
              switch-on: b_descriptor_type
              cases:
                type::string: string
        enums:
          type:
            1: device
            2: configuration
            3: string
        types:
          string:
            seq:
              - id: string
                size-eos: true
                type: str
                encoding: "UTF-16LE"
  disp:
    seq:
      - id: vid
        type: u2
      - id: pid
        type: u2
      - id: desc
        size: 0x40
        type: str
        encoding: "UTF-16LE"
  aud:
    seq:
      - id: vid
        type: u2
      - id: pid
        type: u2
      - id: desc
        size: 0x40
        type: str
        encoding: "UTF-16LE"
  gpio:
    seq:
      - id: unk0
        type: u4
      - id: unk1
        type: u4
      - id: unk2
        type: u4
      - id: unk3
        type: u4
      - id: unk4
        type: u4
      - id: unk5
        type: u4
      - id: unk6
        type: u4
      - id: unk7
        type: u4
      - id: unk8
        type: u4
      - id: unk9
        type: u4
      - id: unk10
        type: u2
      - id: unk11
        type: u2
      - id: unk12
        type: u4
      - id: unk13
        type: u2
      - id: unk14
        type: u2
      - id: unk15
        type: u4
      - id: unk16
        type: u4
      - id: unk17
        type: u4
      - id: unk18
        type: u4
