import json
import os
import subprocess



import serial

subprocess.run(['lsusb'])

with serial.Serial('/dev/ttyUSB0', 9600, timeout=1) as ser:
    ser.write(b'hello')
    print('hello \n')
    line = ser.readline()   # read a '\n' terminated line
    print(line)

