#!/usr/bin/env python3

import sys

ror = lambda val, r_bits, max_bits: \
    ((val & (2**max_bits-1)) >> r_bits%max_bits) | \
    (val << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))

rol = lambda val, r_bits, max_bits: \
    (val << r_bits%max_bits) & (2**max_bits-1) | \
    ((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))


def getkey1(key,start,end):
    i = start + 0x80
    while(i<=(end + 0x80)):
        fh.seek(i);
        ib = int.from_bytes(fh.read(1),byteorder='big')
        key+=ib
        i+=1
    return key

def get_bit(i):
    i=i%8
    return (0x1 << i)

def getkey2(key,start,end,inflag,obfuscator):
    i = start
    while(i<=end):
        bitnum = 0x80
        if inflag==0:
            bitnum=0x1
        fh.seek(i+0x80);
        ib = int.from_bytes(fh.read(1),byteorder='big')
        while True:
            key = key << 1
            test_mask=get_bit(bitnum)
            if key<(2**32):
                if((test_mask & ib)==0):
                    key = key ^ obfuscator
            else:
                key = key & 0xFFFFFFFF
                if((test_mask & ib)!=0):
                    key = key ^ obfuscator
            if (inflag!=0):
                bitnum = ror(bitnum,1,8)
                if ((bitnum & 0x80)!=0):
                    break
            else:
                bitnum = rol(bitnum,1,8)
                if ((bitnum & 0x1)==0x1):
                    break
        i+=1
    return key


def write_decrypt1(start,end,key):
    fh.seek(start+0x80)
    inblock=bytearray(fh.read(end-start+1))
    outblock=decrypt1(key,inblock[:])
    fh.seek(start+0x80)
    fh.write(bytes(outblock))

def decrypt1(key,block):
    def rotate_key(d0,d1,d2):
        if d2==0:
            d0 = ror(d0,d1,32)
        else:
            d0 = rol(d0,d1,32)
        return d0

    i=0
    while i<len(block):
        key_lb = key&0xFF
        i_lb = i&0xFF
        if (i_lb&0x1 == 0):
            key_lb = key_lb & 0xF
        else:
            key_lb = (key_lb >> 4) &0xFFFF
        key = rotate_key(key,key_lb,0)
        ib = block[i]
        key_lb = key&0xFF
        output = ib ^ key_lb
        block[i]=output
        i+=1
    return block


def write_decrypt2(i,end,key,salt):
        fh.seek(i+0x80)
        block=fh.read(end-i+1)
        fh.seek(i+0x80)
        fh.write(decrypt2(block,key,salt))


def swap(inbyte):
    in_th = inbyte>>16
    in_bh = (inbyte & 0xFFFF)
    out = (in_bh << 16) + in_th
    return out

def decrypt2(block,key,salt):
        blockarray=bytearray(block)
        i=0
        while(i<len(blockarray)):
                d2=key
                d4=key
                d2=swap(d2)
                key+=d2
                key=key & 0xFFFF
                d4=swap(d4)
                d4=d4 & 0xFFFF0000
                key+=d4
                key=swap(key)
                key+=salt
                key=key&0xFFFFFFFF
                ib = blockarray[i]
                output=ib ^ (key & 0xFF)
                blockarray[i]=output
                i+=1
        return bytes(blockarray)

def copybytes(source,target,count):
  fh.seek(source+0x80)
  block=fh.read(count)
  fh.seek(target+0x80)
  fh.write(block)

def savebytes(filename,start,end):
    fh.seek(start+0x80)
    oh=open(filename,"wb")
    oh.write(fh.read(end-start+1))
    oh.close()

fh = open("Seven_Cities.bin","r+b")

#round 1
rolling_key=getkey1(0x50414345,0x2dccc,0x305d1)
r1key=getkey1(0x50414345,0x2dccc,0x2de67)
write_decrypt1(0x2de68,0x30642-1,r1key)

#round2
r2key=getkey2(0,0x2dccc,0x2e247,0,0x8005)    #0x2dea4
rolling_key+=getkey2(0x50414345,0x2dccc,0x305d1,0xff,0x8005) #0x2df2a
write_decrypt2(0x2e248,0x30642-1,r2key,0x776de01d) #0x2df44

#round3
r3key=getkey2(0xAAAAAAAA,0x2dccc,0x2fde5,0,0x1021)    #2e2ee  -$24(a6)
rolling_key+=getkey2(0x50414345,0x2dccc,0x305d1,0xff,0x1021) #0x2e7a8 -$20(a6)
r3key=(r3key+0xcb838d42)&0xFFFFFFFF #added from 0x2e810 
write_decrypt2(0x2fde6,0x30641-1,r3key,0xdddaac4d) #0x2e7d6

#round4
r4key=getkey2(0x55555555,0x2de68,0x305d1,0xFF,0x8005)    #2fec4  -$24(a6)
rolling_key+=getkey2(0x50414345,0x2fde6,0x305d1,0x0,0x8005) #2fe9e -$20(a6)
r4key=(r4key+rolling_key)&0xFFFFFFFF #added at 0x2fecc put in -2C(a6)
#replace PACE routine in jump table with application original and decrypt
copybytes(0x30667,0x114,0xD-0x5) #2ff02
write_decrypt2(0x114,0x114+0x28-1,r4key,0xd975bb1d) #0x2ff32

#round5
#decrypt all application code segments now

#bruteforce this instead of stepping through all that code to figure it out
#basically, the first byte of a code segment must be \x00, unless
#the jump table is over 256 bytes (which it isn't in this case)
#so loop until the \x00 has been found.
fh.seek(0x140+0x80)
testbytes=fh.read(1)
i=0
while True:
    outbytes=decrypt2(testbytes,(r4key+i)&0xFFFFFFFF,0xad95322d)
    print(i,outbytes)
    if outbytes==b'\x00':
        break
    i+=1
print("Delta:",i)
r5key = (r4key + i)&0xFFFFFFFF

write_decrypt2(0x140,0x140+0x2260-1,r5key,0xad95322d) #0xCODE1
write_decrypt2(0x23a4,0x23a4+0xcb3e-1,r5key,0xad95322d) #0xCODE2
write_decrypt2(0xeee6,0xeee6+0xc554-1,r5key,0xad95322d) #0xCODE3
write_decrypt2(0x1b43e,0x1b43e+0x6e36-1,r5key,0xad95322d) #0xCODE4
write_decrypt2(0x22278,0x22278+0x8b68-1,r5key,0xad95322d) #0xCODE5
write_decrypt2(0x2ade4,0x2ade4+0x2d0e-1,r5key,0xad95322d) #0xCODE255

fh.close()
