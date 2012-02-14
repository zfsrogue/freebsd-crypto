#!/usr/bin/env python
# Copyright (c) 2012, Neville-Neil Consulting
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
# Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.
#
# Redistributions in binary form must reproduce the above copyright
# notice, this list of conditions and the following disclaimer in the
# documentation and/or other materials provided with the distribution.
#
# Neither the name of Neville-Neil Consulting nor the names of its 
# contributors may be used to endorse or promote products derived from 
# this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# Author: George V. Neville-Neil
#
# $FreeBSD$

# Description: A program to run a simple program against every available
# pmc counter present in a system.
#
# To use:
#
# pmctest.py ls > /dev/null
#
# This should result in ls being run with every available counter
# and the system should neither lock up nor panic.

import sys
import subprocess
from subprocess import PIPE

# A list of strings that are not really counters, just
# name tags that are output by pmccontrol -L
notcounter = ["IAF", "IAP", "TSC", "UNC", "UCF"]

def main():

    if (len(sys.argv) != 2):
        print ("usage: pmctest.py program")

    program = sys.argv[1]

    p = subprocess.Popen(["pmccontrol", "-L"], stdout=PIPE)
    counters = p.communicate()[0]

    if len(counters) <= 0:
        print "no counters found"
        sys.exit()

    for counter in counters.split():
        if counter in notcounter:
            continue
        p = subprocess.Popen(["pmcstat", "-p", counter, program], stdout=PIPE)
        result = p.communicate()[0]
        print result

# The canonical way to make a python module into a script.
# Remove if unnecessary.
 
if __name__ == "__main__":
    main()
