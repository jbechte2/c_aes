CFLAGS = -g -Wall -Wextra

TARGETS = bin/aes
TEST = bin/test
OBJS = obj/aes_tables.o obj/expand_key.o obj/aes_funcs.o
TEST_OBJS = obj/test_expand_key.o obj/test_aes.o obj/run_tests.o

all: $(TARGETS)
test: $(TEST)

$(TARGETS): $(OBJS) obj/aes.o | bin
	$(CC) $(CFLAGS) -o $@ $^

$(TEST): $(TEST_OBJS) $(OBJS) | bin
	$(CC) $(CFLAGS) -o $@ $^

obj/aes.o: src/aes.c | obj
	$(CC) $(CFLAGS) -c -o $@ $^

obj/aes_funcs.o: src/aes_funcs.c | obj
	$(CC) $(CFLAGS) -c -o $@ $^

obj/test_expand_key.o: src/tests/expand_key_test.c | obj
	$(CC) $(CFLAGS) -c -o $@ $^

obj/test_aes.o: src/tests/aes_test.c | obj
	$(CC) $(CFLAGS) -c -o $@ $^

obj/run_tests.o: src/tests/run_tests.c | obj
	$(CC) $(CFLAGS) -c -o $@ $^

obj/expand_key.o: src/expand_key.c | obj
	$(CC) $(CFLAGS) -c -o $@ $^

obj/aes_tables.o: src/aes_tables.c | obj
	$(CC) $(CFLAGS) -c -o $@ $^

obj:
	mkdir -p $@

bin:
	mkdir -p $@

clean:
	rm -f bin/* obj/*.o

