exec(open('bvhstack.py').read().split('md=')[0]); md=Cs(CS_ARCH_X86,CS_MODE_64)
for va in [0xc32f,0xc380,0xc41f,0x24250]:
 for name,sva,vs,rp,rs in secs:
  if sva<=va<sva+max(vs,rs):
   off=rp+va-sva; print('\n',hex(va),name)
   for ins in md.disasm(b[max(rp,off-8):off+240],0x180000000+va-8): print(hex(ins.address),ins.mnemonic,ins.op_str)
   break
