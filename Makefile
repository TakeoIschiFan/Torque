SRC_DIR = src
TEST_DIR = tests
BUILD_DIR = build
SRC_FILES = $(wildcard $(SRC_DIR)/*.c)
TEST_FILES = $(wildcard $(TEST_DIR)/*.c)
SRC_OBJS = $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/src/%.o,$(filter-out $(SRC_DIR)/main.c,$(SRC_FILES)))
TEST_OBJS = $(patsubst $(TEST_DIR)/%.c,$(BUILD_DIR)/tests/%.o,$(TEST_FILES))
MAIN_EXEC = $(BUILD_DIR)/torque
TEST_EXEC = $(BUILD_DIR)/torque_tests

CC = gcc
CFLAGS = -g -Wall -Wextra -pedantic --coverage -std=gnu11 -I$(SRC_DIR) -I$(TEST_DIR)

.PHONY: all
all: $(BUILD_DIR) $(MAIN_EXEC) $(TEST_EXEC)

.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)/src $(BUILD_DIR)/tests

$(BUILD_DIR)/src/%.o: $(SRC_DIR)/%.c $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/tests/%.o: $(TEST_DIR)/%.c $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(MAIN_EXEC): $(SRC_OBJS) $(BUILD_DIR)/src/main.o
	$(CC) $(CFLAGS) -o $(MAIN_EXEC) $(SRC_OBJS) $(BUILD_DIR)/src/main.o

$(TEST_EXEC): $(SRC_OBJS) $(TEST_OBJS)
	$(CC) $(CFLAGS) -o $(TEST_EXEC) $(SRC_OBJS) $(TEST_OBJS) -DTESTS


.PHONY: run
run: $(MAIN_EXEC)
	$(MAIN_EXEC) $(TFILE)

.PHONY: test
test: $(TEST_EXEC)
	$(TEST_EXEC)

.PHONY: leakcheck
leakcheck: $(TEST_EXEC)
	valgrind --leak-check=full --show-leak-kinds=definite,indirect,possible --track-origins=yes $(TEST_EXEC)

.PHONY: cov
cov: test
	@if [ "$(CC)" != "gcc" ]; then \
		echo "Error: CC must be gcc for generating code coverage, current: $(CC)"; \
		exit 1; \
	fi
	lcov --gcov-tool /bin/gcov --quiet --rc branch_coverage=1 --capture --directory $(BUILD_DIR) --output-file $(BUILD_DIR)/coverage.info
	lcov --remove $(BUILD_DIR)/coverage.info 'tests/*'
	genhtml $(BUILD_DIR)/coverage.info --output-directory $(BUILD_DIR)/coverage-html

.PHONY: lint
lint:


.PHONY: check
check: clean lint test cov leakcheck




