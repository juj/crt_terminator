; compile cmdline: "yasm -f bin -o paltsr.com paltsr.asm"

BITS 16
org 0x100

  ; jmp near = 3 bytes, 4 bytes needed for old_isr (overwrites entry point jump)
old_isr:
  jmp near init
  nop
  
pal: times 256*3 db 0
crtt_pal_index: dw 0

update_palette:
  ; N.b. the Palette DAC has a boolean "am I in read mode"
  ; vs "am I in write mode" state. Reading port 0x3C7
  ; is supposed to tell us which one we are currently in,
  ; but that does not seem to work reliably. See
  ; http://www.osdever.net/FreeVGA/vga/colorreg.htm#3C7
  
  mov dx, 0x3C8    ; dx = 0x3C8
  in al, dx        ; al = inp(0x3C8)
  push ax          ; old_dac_write_index
  dec dx           ; dx = 0x3C7
  xor ax, ax
  out dx, al       ; Switch DAC to reading VGA palette index 0

  add dx, 2        ; dx = 0x3C9
  ; si is used to index the local palette memory
  ; bh is used as a counter to iterate through the DAC palette entries
  ; di is used to cache the value of crtt_pal_index
  mov si, pal      
  xor bx, bx       ; set bh to zero
  movzx di, [crtt_pal_index]
.loop:
  in al, dx        ; fetch red
  movzx cx, al
  xchg [si], al
  cmp cl, al       ; compare current red to old red, set/clear EQ flag
  
  in al, dx        ; fetch green
  mov ch, al
  xchg [si+1], al
  jne .blue
  cmp ch, al       ; compare current green to old green, set/clear EQ flag
  
.blue:
  in al, dx        ; fetch blue
  mov bl, al
  xchg [si+2], al
  jne .update      ; if EQ is not clear, update CRTT
  cmp bl, al       ; compare current blue to old blue, set/clear EQ flag
  je .update_done  ; if EQ is clear don't update CRTT
  
.update:
  ; does the CRTT index need to be updated?
  movzx ax, bh              ; ax = i
  cmp di, ax                ; if (i != crtt_pal_index) {
  je .skip_index_update
  

  mov dx, 0x123             ; dx = 0x123
  mov di, ax                ;   crtt_pal_index = i;
  out dx, al                ;   outp(0x123, i)
                            ; }
  
.skip_index_update:
  mov dx, 0x124             ; dx = 0x124
  ; expand 6-bit -> 8-bit by copying 2 MSBs to LSBs
  shrd ax, cx, 6
  shrd ax, cx, 14
  movzx cx, ch
  out dx, al       ; outp(0x124, red)
  shrd ax, cx, 14
  out dx, al       ; outp(0x124, green)
  shrd ax, bx, 6
  shrd ax, bx, 14
  inc di           ; crtt_pal_index++
  out dx, al       ; outp(0x124, red)
  mov dx, 0x3C9    ; dx = 0x3C9

.update_done:
  inc bh           ; increment index - will overflow to zero when 256 is reached
  lea si, [si+3]   ; increment palette pointer (without setting flags)
  jne .loop

  ; Set DAC back to palette write mode, and set the old VGA palette write
  ; index. This assumes that games/programs never rely on the DAC being
  ; left in read mode, and that they disable interrupts while programming
  ; the palette.
  ; (because if interrupts would occur in the middle of writing G or B
  ; component, we cannot reset write index back to that color component)
  pop ax     ; al = old_dac_write_index
  dec dx     ; dx = 0x3C8
  mov [crtt_pal_index], di          ; save crtt pal index for next time
  out dx, al ; outp(0x3C8, old_dac_write_index);

  retn

timer_handler:
  ; push used registers
  push ax
  push bx
  push cx
  push dx
  push si
  push di
  push ds
  mov ax, cs
  mov ds, ax
  
  call update_palette
  
  ; pop used registers
  pop ds
  pop di
  pop si
  pop dx
  pop cx
  pop bx
  pop ax
  
  ; we are done, branch to previous timer routine
  jmp far [cs:old_isr]
  
init:
  ; disable interrupts
  cli
  
  ; initialize crtt
  xor ax, ax
  mov dx, 0x123
  out dx, al  ; Sync initial CRT Terminator palette write index state
  call update_palette
  
  mov cx, 256
  mov bx, pal
.loop:                ; for (bx=&pal[0], i=256; i > 0; i--) {
  xor byte [bx], 0x80 ;   *bx.r ^= 0x80
  add bx, 3           ;   bx++;
  loop .loop          ; }
  
  call update_palette
  
  ; enable interrupts
  sti
  
  ; get old timer routine
  mov ax, 0x351C
  int 0x21
  mov [old_isr], bx
  mov [old_isr+2], es
  
  ; set new timer routine
  mov dx, timer_handler
  ; ds should already be set to our (single) segment
  mov ax, 0x251C
  int 0x21

  ; terminate and stay resident, release all memory after init
  mov dx, (init+15) >> 4
  mov ax, 0x3100
  int 0x21
