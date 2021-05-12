#!/usr/bin/env python3

noops = [ 
          [0xa812,0xa843]
          ]

fh=open("_.bin","r+b")

for myrange in noops:
  i=myrange[0]+0x80
  while i<=(myrange[1]+0x80):
    fh.seek(i)
    fh.write((0x4e71).to_bytes(2,'big'))
    i+=2

fh.close()
