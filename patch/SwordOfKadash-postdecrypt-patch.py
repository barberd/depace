#!/usr/bin/env python3

noops = [ 
          [0x354,0x35d], #jump to CODE 2 and jump if 0 return
          [0x40aa,0x40bd], #jump to code 3 and jump if 0 return
          [0x8fd6,0x8fd7]  #control trap used for saving the game to bypass
                           #read-only lock flag on MFS filesystem
          ]

fh=open("kad_main.bin","r+b")

for myrange in noops:
  i=myrange[0]+0x80
  while i<=(myrange[1]+0x80):
    fh.seek(i)
    fh.write((0x4e71).to_bytes(2,'big'))
    i+=2

fh.close()
