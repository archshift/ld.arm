#!/bin/bash

arm-linux-gnueabi-gcc -mcpu=arm946e-s testbin/testfile.c -shared -o test.elf 

