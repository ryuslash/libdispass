CFLAGS = -lcrypto -fPIC

.PHONY: clean

libdispass.so: dispass.o
	$(CC) $(CFLAGS) -shared -o libdispass.so $^

dispasstest: libdispass.so dispasstest.o
	$(CC) -o dispasstest -L. -ldispass dispasstest.o

clean:
	rm -f dispasstest
	rm -f *.so
	rm -f *.o
