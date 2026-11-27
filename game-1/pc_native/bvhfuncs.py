exec(open('bvhstack.py').read().split('md=')[0])
md=Cs(CS_ARCH_X86,CS_MODE_64)
for va in [0x2303a,0x2302e,0xc2d0,0xd850,0x20270]:
 for name,sva,vs,rp,rs in secs:
  if sva<=va<sva+max(vs,rs):
   off=rp+va-sva; print('\n',hex(va),name)
   for ins in md.disasm(b[off:off+180],0x180000000+va): print(hex(ins.address),ins.mnemonic,ins.op_str)
   break
