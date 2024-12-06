This directory contains PALTSR.ASM contributed by jmarsh.
It is an optimized version of the original C++ version
of PALTSR.CPP that was written in Borland Turbo C++ 3.0.

This assembly version has a much smaller memory footprint,
so prefer to use this version instead of the C++ version.

Run BUILD.BAT to compile the PALTSR.ASM from source to
produce PALTSR.COM.

-----------------------------------------------------------

PALTSR is an assembly program that mirrors the VGA palette
over to CRT Terminator by repeatedly polling the VGA adapter
for the palette, and writing it to CRT Terminators palette
register space.

This enables CRT Terminator output to show proper colors in
scenarios where VGA palette snooping cannot be activated via
other means. Only use this TSR if there are no other palette
snooping methods available.

ISA VGA adapters do not need the use of this TSR, as palette
snooping is always activated there.

Likewise, PCI VGA adapters should not need to use this TSR,
rather instead PCI Palette Snoop can be activated in the
PCI register space itself (run e.g. SNOOP.EXE to activate)

ISA VLB adapters may need this TSR if no other solution
of enabling palette snoop can be found.
