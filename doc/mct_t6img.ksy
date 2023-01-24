meta:
  id: mct_t6img
  file-extension: t6img
  endian: le
  license: CC0-1.0
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
      - id: config_usb2_start
        type: u2
      - id: config_usb3_start
        type: u2
      - id: binary_object_store_start
        type: u2
      - id: unk3_start
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
      config_usb2:
        pos: config_usb2_start - 12
        type: descriptors
        size: config_usb3_start - config_usb2_start
      config_usb3:
        pos: config_usb3_start - 12
        type: descriptors
        size: binary_object_store_start - config_usb3_start
      binary_object_store:
        pos: binary_object_store_start - 12
        type: descriptors
        size: unk3_start - binary_object_store_start
      unk3_inst:
        pos: unk3_start - 12
        type: descriptor
        size: manufacturer_start - unk3_start
      manufacturer:
        pos: manufacturer_start - 12
        type: descriptor
        size: product_start - manufacturer_start
      product:
        pos: product_start - 12
        type: descriptor
    types:
      descriptors:
        seq:
          - id: descriptors
            type: descriptor
            repeat: eos
      descriptor:
        seq:
          - id: b_length
            type: u1
          - id: b_descriptor_type
            type: u1
            enum: type
            if: b_length != 0
          - id: data
            size: b_length - 2
            type:
              switch-on: b_descriptor_type
              cases:
                type::device: device
                type::configuration: configuration
                type::string: string
                type::interface: interface
                type::endpoint: endpoint
                type::binary_object_store: binary_object_store
            if: b_length != 0
        enums:
          type:
            1: device
            2: configuration
            3: string
            4: interface
            5: endpoint
            15: binary_object_store
            16: device_capability
            48: superspeed_usb_endpoint_companion
        types:
          device:
            seq:
              - id: bcd_usb
                type: u2
              - id: b_device_class
                type: u1
              - id: b_device_sub_class
                type: u1
              - id: b_device_protocol
                type: u1
              - id: b_max_packet_size
                type: u1
              - id: id_vendor
                type: u2
              - id: id_product
                type: u2
              - id: bcd_device
                type: u2
              - id: i_manufacturer
                type: u1
              - id: i_product
                type: u1
              - id: i_serial_number
                type: u1
              - id: b_num_configurations
                type: u1
          configuration:
            seq:
              - id: w_total_length
                type: u2
              - id: b_num_interfaces
                type: u1
              - id: b_configuration_value
                type: u1
              - id: i_configuration
                type: u1
              - id: bm_attributes
                size: 1
              - id: b_max_power
                type: u1
          string:
            seq:
              - id: string
                size-eos: true
                type: str
                encoding: "UTF-16LE"
          interface:
            seq:
              - id: b_interface_number
                type: u1
              - id: b_alternate_setting
                type: u1
              - id: b_num_endpoints
                type: u1
              - id: b_interface_class
                type: u1
              - id: b_interface_sub_class
                type: u1
              - id: b_interface_protocol
                type: u1
              - id: i_interface
                type: u1
          endpoint:
            seq:
              - id: b_endpoint_address
                type: u1
              - id: bm_attributes
                size: 1
              - id: w_max_packet_size
                type: u2
              - id: b_interval
                type: u1
          binary_object_store:
            seq:
              - id: w_total_length
                type: u2
              - id: b_num_device_caps
                type: u1
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
      - id: unk0
        type: u4
      - id: unk1
        type: u4
      - id: unk2
        type: u4
      - id: unk3
        type: u4
      - id: unk4
        size: 16
      - id: modes
        size: 32
        type: mode
        repeat: eos
    enums:
      sync_polarity:
        0: negative
        1: positive
    types:
      mode:
        seq:
          - id: pixel_clock_khz
            type: u4
          - id: refresh_rate_hz
            type: u2
          - id: line_total_pixels
            type: u2
          - id: line_active_pixels
            type: u2
          - id: line_active_plus_front_porch_pixels
            type: u2
          - id: line_sync_width
            type: u2
          - id: frame_total_pixels
            type: u2
          - id: frame_active_pixels
            type: u2
          - id: frame_active_plus_front_porch_pixels
            type: u2
          - id: frame_sync_width
            type: u2
          - id: unk8
            type: u2
          - id: unk9
            type: u2
          - id: unk10
            type: u2
          - id: sync_polarity_0
            type: u1
            enum: sync_polarity
          - id: sync_polarity_1
            type: u1
            enum: sync_polarity
          - id: unk11
            type: u2
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
