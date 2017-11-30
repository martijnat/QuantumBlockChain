#!/usr/bin/env python2

# Copyright (C) 2017  Martijn Terpstra

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from util import *
import sys
import os

class Blockchain():

    def __init__(self, s=""):
        self.s = s
        self.lasthash = "\0"*32

    def verify(self):
        self.lasthash = "\0"*32
        self.data = ""
        for i in range(0,len(self.s),64):
            data = self.s[i:i+32]
            n = self.s[i:i+32]
            h = sha256(self.lasthash+data+n)
            if not self.hash_hardness(h,i//64):
                return False
            self.lasthash=h
            self.data += data
        return True

    def mine(self,data):
        self.verify()
        data = null_padding(data,32)
        i = len(self.s)//64
        counter = 0
        n = int2bigendian(counter,32)
        h = sha256(self.lasthash+data+n)
        sha256(self.lasthash+data+n)
        while not self.hash_hardness(h,i):
            counter +=1
            n = int2bigendian(counter,32)
            h = sha256(self.lasthash+data+n)
        self.s += data
        self.s += n

    def hash_hardness(self,h,n):
        x = bigendian2int(h)+n
        m = n//32
        for i in range(m):
            if (x&(1<<i))==0:
                return False
        return True

    def __repr__(self):
        self.verify()
        return self.data


if __name__=="__main__":
    b = Blockchain()
    data = sys.stdin.read(32)
    i = 0
    while len(data)>0:
        sys.stdout.write("Mining block %i -> "%i)
        sys.stdout.flush()
        b.mine(data)
        sys.stdout.write(hexstr(b.s[-64:])+"\n")
        i+=1
        data = sys.stdin.read(32)
    print "Blockchain content:"
    print repr(b)
