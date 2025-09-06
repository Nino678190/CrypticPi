import serial
ser = serial.Serial('/dev/ttyUSB0', timeout=1)
print(ser.name)   
ser.write(b'hello') # Send a byte string
ser.close()        # Close the port