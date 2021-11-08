CLANG ?= clang-12
CFLAGS := -O2 -Wall -Werror

all: clean simple semaphore lint

lint:
	black .
	isort .

simple:
	$(CLANG) $(CFLAGS) simple.c -o simple.o

semaphore:
	dtrace -G -s provider.d -o provider.so
	dtrace -h -s provider.d -o provider.h
	$(CLANG) $(CFLAGS) semaphore.c provider.so -o semaphore.o

clean:
	rm -f provider.h
	find . -name "*.o" -type f -delete
	find . -name "*.so" -type f -delete
