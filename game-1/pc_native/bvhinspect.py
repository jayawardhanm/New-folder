import struct
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
p=r'E:\GTA 6\GTA6.Xbox.v1.0.2.1-CYBERLEEK\XboxBvhBuilder.dll'; b=open(p,'rb').read(); pe=struct.unpack_from('<I',b,0x3c)[0]; n=struct.unpack_from('<H',b,pe+6)[0]; opt=pe+24; sh=opt+struct.unpack_from('<H',b,pe+20)[0]
secs=[]
for i in range(n):
 o=sh+40*i; name=b[o:o+8].split(b'\0')[0].decode(); vs,va,rs,rp=struct.unpack_from('<IIII',b,o+8); secs.append((name,va,vs,rp,rs))
print(secs)
for va in [0xd2538,0xd2528,0xd24f9,0xd23c5]:
 for name,sva,vs,rp,rs in secs:
  if sva<=va<sva+max(vs,rs):
   off=rp+va-sva; md=Cs(CS_ARCH_X86,CS_MODE_64)
   print('\n',hex(va),name)
   for ins in md.disasm(b[max(0,off-96):off+96],0x180000000+va-96): print(hex(ins.address),ins.mnemonic,ins.op_str)
   break
