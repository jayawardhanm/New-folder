exec(open('peinspect_tmp.py').read().split('for va in [')[0])
md=Cs(CS_ARCH_X86,CS_MODE_64)
for va in [0xc468,0x203b7,0xd8a1,0x213a1,0x2479455-0x140000000,0x19f4f54,0x1580437e,0x143a4911,0x1224070b,0x123cf00a,0x12215eca]:
 for name,sva,vs,rp,rs in secs:
  if sva<=va<sva+max(vs,rs):
   off=rp+va-sva; print('\n',hex(va),name)
   for ins in md.disasm(b[max(0,off-40):off+16],0x140000000+va-40): print(hex(ins.address),ins.mnemonic,ins.op_str)
   break
