mov cl, ch
cmp cl, 65
jge to_lower

sub cl, 0x20
jmp end

to_lower:
add cl, 0x20

end:
mov ch, cl
done: