CFLAGS = -lcrypto -fPIC

libdispass.so: dispass.o
	$(CC) $(CFLAGS) -shared -o libdispass.so $^

dispasstest: libdispass.so dispasstest.o
	$(CC) -o dispasstest -L. -ldispass dispasstest.o
