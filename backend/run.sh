#!/bin/bash

/opt/cmake/bin/cmake -G Ninja -B build . && ninja -C build && ./build/sniffsniff file pcap/wpa_induction.pcap
