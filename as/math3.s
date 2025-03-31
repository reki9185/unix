mov eax, [0x6ae000]
imul eax, 5
mov ebx, [0x6ae004]
sub ebx, 3
idiv ebx
mov [0x6ae008], eax
done: