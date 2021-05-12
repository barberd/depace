#!/usr/bin/env python3

import sys

ror = lambda val, r_bits, max_bits: \
    ((val & (2**max_bits-1)) >> r_bits%max_bits) | \
    (val << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))

rol = lambda val, r_bits, max_bits: \
    (val << r_bits%max_bits) & (2**max_bits-1) | \
    ((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))


def getkey1(start,end):
    key = int("0x50414345",0)
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

fh = open("_.bin","r+b")

#round 1
key= getkey1(0xb504,0xb669)
key2 = getkey1(0xb504,0xd019)
write_decrypt1(0xb66a,0xd088-1,key)

#round 2
key= getkey2(0,0xb504,0xb9b5,0,0x8005) 
key2 = (key2 + getkey2(0x50414345,0xb504,0xd019,0xFF,0x8005)) & 0xFFFFFFFF
write_decrypt2(0xb9b6,0xd080-1,key,0x776de01d)

#round 3
key= (getkey2(0xAAAAAAAA,0xb504,0xc835,0,0x1021) + 0x41BA) & 0xFFFFFFFF
key2 = (key2 + getkey2(0x50414345,0xb504,0xd019,0xFF,0x1021)) & 0xFFFFFFFF
write_decrypt2(0xc836,0xd07f-1,key,0xdddaac4d)

#round 4 (jump table and code tables)
key= getkey2(0x55555555,0xb66a,0xd019,0xFF,0x8005) & 0xFFFFFFFF
key = (key + key2 + getkey2(0x50414345,0xc836,0xd019,0x0,0x8005)) & 0xFFFFFFFF
copybytes(0xd08f,0x114,0xD-0x5)
write_decrypt2(0x114,0x784-1,key,0xd975bb1d)

#bruteforce the key. Use CODE1's first byte as the target.
i=0
fh.seek(0x788 + 0x80)
testblock=bytearray(fh.read(1))
while i<0xFF:
    testkey = (key+i)&0xFFFFFFFF
    outblock=decrypt2(testblock[:],testkey,0xad95322d)
    if outblock[0]==0:
        print("Key add:",hex(i),outblock)
        break
    i+=1

key=testkey
write_decrypt2(0x788,0x788+0x23A-1,key,0xad95322d) #CODE1
write_decrypt2(0x9c6,0x9c6+0x4bb0-1,key,0xad95322d) #CODE2
write_decrypt2(0x557a,0x557a+0x21ec-1,key,0xad95322d) #CODE3
write_decrypt2(0x776a,0x776a+0x3282-1,key,0xad95322d) #CODE4
write_decrypt2(0xa9f0,0xa9f0+0x352-1,key,0xad95322d) #CODE5
write_decrypt2(0xad46,0xad46+0x570-1,key,0xad95322d) #CODE6
write_decrypt2(0xb2ba,0xb2ba+0x5e-1,key,0xad95322d) #CODE255

fh.close()
