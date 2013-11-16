CFLAGS = -lcrypto -fPIC

libdispass.so: dispass.o
	$(CC) $(CFLAGS) -shared -o libdispass.so $^
