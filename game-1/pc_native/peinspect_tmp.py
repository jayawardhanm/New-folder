import struct
from capstone import *
p=r'E:\GTA 6\GTA6.Xbox.v1.0.2.1-CYBERLEEK\game_scarlett_master.exe'
b=open(p,'rb').read(); pe=struct.unpack_from('<I',b,0x3c)[0]; n=struct.unpack_from('<H',b,pe+6)[0]; opt=pe+24; magic=struct.unpack_from('<H',b,opt)[0]; sh=opt+struct.unpack_from('<H',b,pe+20)[0]
secs=[]
for i in range(n):
 o=sh+40*i; name=b[o:o+8].split(b'\0')[0].decode(); vs,va,rs,rp=struct.unpack_from('<IIII',b,o+8); secs.append((name,va,vs,rp,rs))
print(secs)
for va in [0x1647616,0x16475f0,0xd2538,0xcdbe8,0xc468,0x203b7,0xd8a1]:
 for name,sva,vs,rp,rs in secs:
  if sva<=va<sva+max(vs,rs):
   off=rp+va-sva; md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=True
   print('\n',hex(va),name)
   for ins in md.disasm(b[off-48:off+48],0x140000000+va-48): print(hex(ins.address),ins.mnemonic,ins.op_str)
   break
