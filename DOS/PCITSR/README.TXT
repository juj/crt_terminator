PCITSR.EXE implements a special type of TSR that keeps polling for the PCI VGA
adapter palette snoop status, and force-enables it whenever it is seen to be
disabled.

This TSR fixes up incorrect palette with CRT Terminator specifically on the
Diamond Speedstar 64 CL-GD5434 VGA adapter, which has a buggy firmware that it
resets the PCI palette snoop status on every video mode change.

The vast majority of PCI adapters do not need to use this TSR, instead they can
just use SNOOP.EXE to enable the PCI palette snoop status once at boot, e.g.
in AUTOEXEC.BAT and it will persist.
