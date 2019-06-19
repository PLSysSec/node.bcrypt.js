{
  'targets': [
    {
      'target_name': 'bcrypt_lib',
      'sources': [
        'src/bcrypt_node.cc'
      ],
      "cflags_cc": [ "-g3", "-std=c++14", "-Wl,--export-dynamic", "-ldl" ],
      'include_dirs' : [
          "<!(node -e \"require('nan')\")"
      ],
      'conditions': [
        [ 'OS=="win"', {
          'defines': [
            'uint=unsigned int',
          ],
        }],
      ],
    },
    {
      "target_name": "action_after_build",
      "type": "none",
      "dependencies": [ "<(module_name)" ],
      "copies": [
        {
          "files": [ "<(PRODUCT_DIR)/<(module_name).node" ],
          "destination": "<(module_path)"
        }
      ]
    }
  ]
}
