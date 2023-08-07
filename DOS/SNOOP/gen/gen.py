from struct import *

lines = open('pci.ids.txt', 'r').read().split('\n')

string_list = bytearray()
strings = {}
max_string_length = 0

def add_string(s):
  global strings, string_list, max_string_length
  if s in strings: return
  strings[s] = len(string_list)
#  print(f'{len(string_list)}: {s}')
  max_string_length = max(max_string_length, len(s)+1) # account for null byte
  string_list += s.encode('utf-8') + b'\0'

add_string('<internal error>') # Reserve pointer offset 0 for an error field

vendors = {}
devices = {}
subdevices = {}

vendor = 0
for l in lines:
  if len(l) == 0 or l[0] == '#': continue
  if l[0] != '\t':
    vendor = int(l[0:4], 16)
    name = l[6:].strip()
    vendors[vendor] = name
#    print(l)
    add_string(name)
    continue
  if l[1] != '\t':
    device = int(l[1:5], 16)
    name = l[7:].strip()
    code = (vendor << 16) | device
    devices[code] = name
    add_string(name)
    #print('device: ' + hex(code) + ' ' + name)
    continue
  if l[2] != '\t':
    subvendor = int(l[2:6], 16)
    subdevice = int(l[7:11], 16)
    name = l[13:]
    c = (code << 32) | (subvendor << 16) | subdevice
    subdevices[c] = name
    add_string(name)
#    print('subdevice: ' + hex(c) + ' ' + hex(subvendor) + ' ' + hex(subdevice) + ' ' + name)

#open('PCI.STR', 'wb').write(string_list)
#print(f'Wrote pci.str with {len(string_list)} bytes. Max string length: {max_string_length}')

################################################# Hash Vendors
num_collisions = 0
longest_probe = 0

fold32_0 = 16025929
fold32_1 = 15448861
def find_hash_function(data_dict, hash_table_len, min_val, max_val, hash_fn):
  global num_collisions, longest_probe
  num_collisions = 0
  longest_probe = 0
  def test_hash(mul):
    global num_collisions, longest_probe
    longest_probe = 0
    num_collisions = 0
    hash_table = [None] * hash_table_len

    def hash_device(e):
      global num_collisions, longest_probe
      nonlocal hash_table
      val = (e * mul) & 0xFFFFFFFF
      i = val % hash_table_len
      probe = 1
      while hash_table[i] != None:
        i += 1
        if i >= len(hash_table): hash_table += [None]
        num_collisions += 1
        probe += 1
      if probe > longest_probe:
        longest_probe = probe
      return i

    def hash_subvendor(e):
      global num_collisions, longest_probe
      nonlocal hash_table
      val0 = e >> 32
      val1 = e & 0xFFFFFFFF
      val = (val0 * fold32_0) ^ (val1 * fold32_1)
      val = val & 0xFFFFFFFF
      i = ((val * mul) & 0xFFFFFFFF) % hash_table_len
      probe = 1
      while hash_table[i] != None:
        i += 1
        if i >= len(hash_table): hash_table += [None]
        num_collisions += 1
        probe += 1
      if probe > longest_probe:
        longest_probe = probe
      return i

    for key, name in data_dict.items():
      if hash_fn == 3: idx = hash_subvendor(key)
      else: idx = hash_device(key)

      hash_table[idx] = key
    return num_collisions, hash_table

  bestc = 1e99
  best_mul = 0
  best_longest_probe = 1e99
  best_hash_table = None
  for mul in range(min_val, min(max_val+1, hash_table_len)):
    nc, hash_table = test_hash(mul)
    if longest_probe < best_longest_probe:
      best_mul = mul
      bestc = nc
      best_longest_probe = longest_probe
      best_hash_table = hash_table
      print(f'Num collisions with mul {mul}: {nc}, longest probe: {best_longest_probe}')

  return best_hash_table, best_mul, best_longest_probe

pci_str_h = f'''#ifndef PCI_STR_H
#define PCI_STR_H

#if defined(__TURBOC__) && defined(__MSDOS__)
typedef unsigned int  uint16;
typedef unsigned long uint32;
#else
typedef unsigned short uint16;
typedef unsigned long uint32;
#endif
const char *pci_vendor_str(uint16 vendor);
const char *pci_device_str(uint16 vendor, uint16 device);
const char *pci_subdevice_str(uint16 vendor, uint16 device, uint16 subvendor, uint16 subdevice);
#endif
'''
open('PCI_STR.H', 'w').write(pci_str_h)

###################### VENDORS

vendors_len = 4093
#best_hash_table, best_mul, best_longest_probe = find_hash_function(vendors, vendors_len, 0, vendors_len-1, 1)
vendors_hash_table, vendors_mul, vendors_longest_probe = find_hash_function(vendors, vendors_len, 165, 165, 1)
print(f'')
print(f'Vendors: {len(vendors)}')
print(f'Hash table desired length: {vendors_len}, effective length: {len(vendors_hash_table)}')
print(f'Multiplier: {vendors_mul}')
print(f'Probe distance: {vendors_longest_probe}')
print(f'')

#vendors_hsh = open('VENDORS.HSH', "wb")
vendors_hsh = bytearray()
idx = 0
for vendor in vendors_hash_table:
  str_offset = 0
  if vendor != None: str_offset = strings[vendors[vendor]]
  else: vendor = 0
  str_offset_lo = str_offset & 0xFFFF
  str_offset_hi = (str_offset >> 16) & 0xFFFF
  idx += 1
  #vendors_hsh.write(pack('<HHH', vendor, str_offset_lo, str_offset_hi))
  vendors_hsh.extend(pack('<HHH', vendor, str_offset_lo, str_offset_hi))
for i in range(vendors_longest_probe-1): # Pad end of hash table with zeros so that garbage won't be read at the end
  vendors_hsh.extend(pack('<HHH', 0, 0, 0))

################ Devices

devices_len = 32749
#devices_hash_table, devices_mul, devices_longest_probe = find_hash_function(devices, devices_len, 0, devices_len-1, 2)
devices_hash_table, devices_mul, devices_longest_probe = find_hash_function(devices, devices_len, 30195, 30195, 2)
print(f'')
print(f'Devices: {len(devices)}')
print(f'Hash table desired length: {devices_len}, effective length: {len(devices_hash_table)}')
print(f'Multiplier: {devices_mul}')
print(f'Probe distance: {devices_longest_probe}')
print(f'')
#print(str(devices_hash_table))

#devices_hsh = open('DEVICES.HSH', "wb")
devices_hsh = bytearray()
for vd in devices_hash_table:
  str_offset = 0
  if vd != None: str_offset = strings[devices[vd]]
  else: vd = 0
  devices_hsh.extend(pack('<LL', vd, str_offset))
for i in range(devices_longest_probe-1): # Pad end of hash table with zeros so that garbage won't be read at the end
  devices_hsh.extend(pack('<LL', 0, 0))

################ Subdevices

subdevs_len = 32749
#subdevs_hash_table, subdevs_mul, subdevs_longest_probe = find_hash_function(subdevices, subdevs_len, 0, subdevs_len-1, 3)
subdevs_hash_table, subdevs_mul, subdevs_longest_probe = find_hash_function(subdevices, subdevs_len, 4962, 4962, 3)
print(f'')
print(f'Subdevices: {len(subdevices)}')
print(f'Hash table desired length: {subdevs_len}, effective length: {len(subdevs_hash_table)}')
print(f'Multiplier: {subdevs_mul}')
print(f'Probe distance: {subdevs_longest_probe}')
print(f'')

#subdev_hsh = open('SUBDEV.HSH', "wb")
subdev_hsh = bytearray()
for subdev in subdevs_hash_table:
  str_offset = 0
  if subdev != None: str_offset = strings[subdevices[subdev]]
  else: subdev = 0
  vd = subdev >> 32
  svd = subdev & 0xFFFFFFFF
  subdev_hsh.extend(pack('<LLL', vd, svd, str_offset))
for i in range(subdevs_longest_probe-1): # Pad end of hash table with zeros so that garbage won't be read at the end
  subdev_hsh.extend(pack('<LLL', 0, 0, 0))

############# Generate data file

devices_start_offset = len(vendors_hsh)
subdevs_start_offset = devices_start_offset + len(devices_hsh)
strings_start_offset = subdevs_start_offset + len(subdev_hsh)
pci_id_hsh = open('PCI_ID.HSH', 'wb')
pci_id_hsh.write(vendors_hsh)
pci_id_hsh.write(devices_hsh)
pci_id_hsh.write(subdev_hsh)
pci_id_hsh.write(string_list)

############# Generate PCI_STR.CPP

open('PCI_STR.CPP', 'w').write(f'''#include "pci_str.h"
#include <stdio.h>

static char tmp[{max_string_length+1}] = {{0}};
static const char unknown[] = "(unknown)";

static const char *read_pci_str(FILE *f, uint32 offset)
{{
  fseek(f, {strings_start_offset}ul + offset, SEEK_SET);
  int read = fread(tmp, 1, {max_string_length}, f);
  fclose(f);
  return read > 0 ? tmp : unknown;
}}

const char *pci_vendor_str(uint16 vendor)
{{
  FILE *f = fopen("pci_id.hsh", "rb");
  if (!f) return "";
  uint32 idx = ((uint32)vendor * {vendors_mul}) % {vendors_len};
#define VENDOR_HASH_SIZE 6
  fseek(f, idx*VENDOR_HASH_SIZE, SEEK_SET);
#define LONGEST_VENDOR_PROBE {vendors_longest_probe}
  struct {{ uint16 vendor; uint16 ofsLo; uint16 ofsHi; }} hash[LONGEST_VENDOR_PROBE] = {{0}};
  fread(hash, VENDOR_HASH_SIZE, LONGEST_VENDOR_PROBE, f);
  for(int i = 0; i < LONGEST_VENDOR_PROBE; ++i)
    if (hash[i].vendor == vendor)
    {{
      uint32 offset = (uint32)hash[i].ofsLo | ((uint32)hash[i].ofsHi << 16);
      return read_pci_str(f, offset);
    }}
  fclose(f);
  return unknown;
}}

const char *pci_device_str(uint16 vendor, uint16 device)
{{
  FILE *f = fopen("pci_id.hsh", "rb");
  if (!f) return "";
  uint32 vd = ((uint32)vendor << 16) | device;
  uint32 idx = (vd * {devices_mul}) % {devices_len};
#define DEV_HASH_SIZE 8
  fseek(f, {devices_start_offset}ul + idx*DEV_HASH_SIZE, SEEK_SET);
#define LONGEST_DEV_PROBE {devices_longest_probe}
  struct {{ uint32 vd; uint32 ofs; }} hash[LONGEST_DEV_PROBE] = {{0}};
  fread(hash, DEV_HASH_SIZE, LONGEST_DEV_PROBE, f);
  for(int i = 0; i < LONGEST_DEV_PROBE; ++i)
    if (hash[i].vd == vd)
      return read_pci_str(f, hash[i].ofs);
  fclose(f);
  return unknown;
}}

const char *pci_subdevice_str(uint16 vendor, uint16 device, uint16 subvendor, uint16 subdevice)
{{
  FILE *f = fopen("pci_id.hsh", "rb");
  if (!f) return "";
  uint32 vd = ((uint32)vendor << 16) | device;
  uint32 svd = ((uint32)subvendor << 16) | subdevice;
  uint32 idx = (vd * {fold32_0}ul) ^ (svd * {fold32_1}ul);
  idx = (idx * {subdevs_mul}) % {subdevs_len};
#define SUBDEV_HASH_SIZE 12
  fseek(f, {subdevs_start_offset}ul + idx*SUBDEV_HASH_SIZE, SEEK_SET);
#define LONGEST_SUBDEV_PROBE {subdevs_longest_probe}
  struct {{ uint32 vd; uint32 svd; uint32 ofs; }} hash[LONGEST_SUBDEV_PROBE] = {{0}};
  fread(hash, SUBDEV_HASH_SIZE, LONGEST_SUBDEV_PROBE, f);
  for(int i = 0; i < LONGEST_SUBDEV_PROBE; ++i)
    if (hash[i].vd == vd && hash[i].svd == svd)
      return read_pci_str(f, hash[i].ofs);
  fclose(f);
  return unknown;
}}
''')

############# Generate test

def escape(name):
  return name.replace('"', '\\"')

tests = ''
for vendor_id, name in vendors.items():
  tests += f'  assert(!strcmp(pci_vendor_str({hex(vendor_id)}), "{escape(name)}"));\n'

for device_id, name in devices.items():
  v = device_id >> 16
  d = device_id & 0xFFFF
  tests += f'  assert(!strcmp(pci_device_str({hex(v)}, {hex(d)}), "{escape(name)}"));\n'

for device_id, name in subdevices.items():
  vd = device_id >> 32
  svd = device_id & 0xFFFFFFFF
  v = vd >> 16
  d = vd & 0xFFFF
  sv = svd >> 16
  sd = svd & 0xFFFF
  tests += f'  assert(!strcmp(pci_subdevice_str({hex(v)}, {hex(d)}, {hex(sv)}, {hex(sd)}), "{escape(name)}"));\n'

test_cpp = open('TEST.CPP', 'w').write(f'''#include "pci_str.h"
#include <string.h>
#include <assert.h>

int main()
{{
{tests}
}}
''')
