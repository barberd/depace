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

fh = open("D.bin","r+b")

#round 1
key= getkey1(0x5204,0x5369) # 0x5234
key2 = getkey1(0x5204,0x6d19)  # 0x5220
write_decrypt1(0x536a,0x6d88-1,key)  # 0x524C

#round 2
key= getkey2(0,0x5204,0x56b5,0,0x8005)  #0x539E
key2 = key2 + getkey2(0x50414345,0x5204,0x6d19,0xFF,0x8005) #0x5406
write_decrypt2(0x56b6,0x6d80-1,key,0x776de01d) # 0x5424

#round 3
key= (getkey2(0xAAAAAAAA,0x5204,0x6535,0,0x1021) + 0xF085) & 0xFFFFFFFF #0x5738
# the 0xf085 is loaded in at 0x56c8
key2 = key2 + getkey2(0x50414345,0x5204,0x6d19,0xFF,0x1021) # 0x595C-0x5960
write_decrypt2(0x6536,0x6d7f-1,key,0xdddaac4d)  # 0x598E

#round 4 (jump table and code tables)
key= getkey2(0x55555555,0x536a,0x6d19,0xFF,0x8005)  # 0x65F4
key = (key + key2 + getkey2(0x50414345,0x6536,0x6d19,0x0,0x8005)) & 0xFFFFFFFF # 0x65CE-0x65D2

#the entire jump table was encrypted, then the first 8 bytes stored in CODE4.
#then an entry jumping to the PACE code was put in.
#round4 copies these 8 bytes out of CODE4, restoring the entire applications
#jump table and then decrypts it
#0x66F0 says this is stored in CODE4
#0x65ac loads it into memory and copies it over the jump 
copybytes(0x6d8f,0x114,0xD-0x5)
#decryption happens at 0x6654
write_decrypt2(0x114,0x114+0x88-1,key,0xd975bb1d)

#bruteforce this instead of stepping through all the code
#between 0x57b0 and 0x492F to figure out what to add at 0x669a
#basically, the first byte of a code segment must be \x00, unless
#the jump table is over 256 bytes (which it isn't in this case)
#so loop until the \x00 has been found.
#this only works because the encryption algorithm really only uses the last
#single byte of the key...so really there are only 256 possibilities.
#no idea why PACE didnt use all 32 bits available to them; it would have
#been much more difficult
i=0
fh.seek(0x1a0 + 0x80) #use the first byte of CODE1 as the target
testblock=bytearray(fh.read(1))
while i<0xFF:
    testkey = (key+i)&0xFFFFFFFF
    outblock=decrypt2(testblock[:],testkey,0xad95322d)
    if outblock[0]==0:
        print("Key add:",hex(i),outblock)
        break
    i+=1
key=testkey

#with this key, PACE now decrypts anything in memory at 0x66AE
#and then overloads the trap to load a new code segment to decrypt
#them on the fly at 0x66C6. This way, it still works when the Macintosh
#memory manager swaps code segments in from disk and out from memory.
write_decrypt2(0x1a0,0x1a0+0x4544-1,key,0xad95322d) #CODE1
write_decrypt2(0x46e8,0x46e8+0x3a4-1,key,0xad95322d) #CODE2
write_decrypt2(0x4a90,0x4a90+0x570-1,key,0xad95322d) #CODE3
write_decrypt2(0x5004,0x5004+0x46-1,key,0xad95322d) #CODE255

fh.close()

