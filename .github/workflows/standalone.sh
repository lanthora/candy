name: standalone

on:
  workflow_dispatch:
    inputs:
      all:
        description: 'Build all targets'
        type: boolean
        required: false
      arch:
        description: 'CANDY_ARCH'
        type: environment
        required: false
      os:
        description: 'CANDY_OS'
        type: environment
        required: false
      target:
        description: 'TARGET'
        type: environment
        required: false
      target_openssl:
        description: 'TARGET_OPENSSL'
        type: environment
        required: false

jobs:
  all:
    if: ${{ inputs.all }}
    strategy:
      fail-fast: false
      matrix:
        arch: [aarch64,arm-eabi,mips,mipsel,x86_64]
        os: [linux]
    runs-on: ubuntu-latest
    steps:     
      - name: Checkout
        uses: actions/checkout@v4
      - name: Cross compile
        run: |
          ./scripts/build-single-file-exe.sh
        env:
          CANDY_WORKSPACE: "/tmp/candy"
          CANDY_ARCH: ${{ matrix.arch }}
          CANDY_OS: ${{ matrix.os }}
  one:
    if: ${{ ! inputs.all }}
    runs-on: ubuntu-latest
    steps:     
      - name: Checkout
        uses: actions/checkout@v4
      - name: Cross compile
        run: |
          ./scripts/build-single-file-exe.sh
        env:
          CANDY_WORKSPACE: "/tmp/candy"
          CANDY_ARCH: ${{ input.arch }}
          CANDY_OS: ${{ input.os }}
          TARGET: ${{ input.target }}
          TARGET_OPENSSL: ${{ input.target_openssl }}
