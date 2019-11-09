{
  'targets': [
    {
      'target_name': 'bcrypt_lib',
      'sources': [
        'src/bcrypt_node.cc',
      ],
      "cflags_cc": [ "-g3", "-std=c++14", "-Wl,--export-dynamic", "-ldl",
            "-pie", "-Wl,-z,relro", "-Wl,-z,now", "-Wl,-z,noexecstack", "-fPIC", 
            "-Wl,-rpath=../../Sandboxing_NaCl/native_client/scons-out-firefox/opt-linux-x86-64/lib",
      ],
      'include_dirs' : [
          "<!(node -e \"require('nan')\")",
          "../../rlbox_api",
          "../../Sandboxing_NaCl/native_client/src/trusted/dyn_ldr/",
      ],
      "libraries" : [
          "-L../../../Sandboxing_NaCl/native_client/scons-out-firefox/opt-linux-x86-64/lib",
          "-ldyn_ldr", "-lsel", "-lnacl_error_code", "-lenv_cleanser", "-lnrd_xfer",
          "-lnacl_perf_counter", "-lnacl_base", "-limc", "-lnacl_fault_inject", "-lnacl_interval",
          "-lplatform_qual_lib", "-lvalidators", "-ldfa_validate_caller_x86_64", "-lcpu_features",
          "-lvalidation_cache", "-lplatform", "-lgio", "-lnccopy_x86_64", "-lrt", "-lpthread",
      ],
      "defines" : [
        "RLBOX_NACL"
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
