mov esi, 0
sub esi, [0x69e004]
imul esi, [0x69e000]

mov edi, [0x69e008]
sub edi, ebx

mov eax, esi
cdq
idiv edi

mov [0x69e008], eax
done: