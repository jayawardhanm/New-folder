import struct
b=open(r'E:\GTA 6\GTA6.Xbox.v1.0.2.1-CYBERLEEK\XboxBvhBuilder.dll','rb').read(); pe=struct.unpack_from('<I',b,0x3c)[0]; n=struct.unpack_from('<H',b,pe+6)[0]; opt=pe+24; magic=struct.unpack_from('<H',b,opt)[0]; dd=opt+(112 if magic==0x20b else 96); sh=opt+struct.unpack_from('<H',b,pe+20)[0]; secs=[]
for i in range(n):
 o=sh+40*i; name=b[o:o+8].split(b'\0')[0].decode(); vs,va,rs,rp=struct.unpack_from('<IIII',b,o+8); secs.append((va,max(vs,rs),rp,name))
def off(rva):
 for va,size,rp,name in secs:
  if va<=rva<va+size:return rp+rva-va
 return 0
def cstr(rva): return b[off(rva):].split(b'\0')[0].decode(errors='replace')
irva,isize=struct.unpack_from('<II',b,dd+8)
print('import',hex(irva),hex(isize))
pos=off(irva)
while True:
 oft,ts,fc,nrv,ft=struct.unpack_from('<IIIII',b,pos); pos+=20
 if not any((oft,ts,fc,nrv,ft)):break
 dll=cstr(nrv); print('\nDLL',dll,'ft',hex(ft))
 th=off(oft or ft)
 i=0
 while True:
  v=struct.unpack_from('<Q',b,th+8*i)[0]
  if not v:break
  if v>>63: nm=f'ordinal {v&0xffff}'
  else: nm=cstr(v+2)
  r=ft+8*i
  if 0x24200<=r<0x24300: print('***',hex(r),nm)
  else: print(hex(r),nm)
  i+=1
