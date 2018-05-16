all: release

.PHONY: clean
clean:
	rm -rf ./bin/
	rm -rf ./doc/

doc: Doxyfile
	doxygen Doxyfile

debug: src
	mkdir -p ./bin/debug/
	$(MAKE) debug -C src 

debug-prof-test: debug
	sudo valgrind -v --track-fds=yes --error-limit=no --tool=memcheck --leak-check=yes bin/debug/goose_ping lo

debug-test: 
	sudo bin/debug/goose_ping lo

pi-debug: src
	mkdir -p ./bin/raspberry-pi_debug/
	$(MAKE) pi-debug -C src 

pi-release: src
	mkdir -p ./bin/raspberry-pi_release/
	$(MAKE) pi-release -C src 

release: src
	mkdir -p ./bin/release/
	$(MAKE) release -C src 

release-prof-test: release
	sudo valgrind -v --track-fds=yes --error-limit=no --tool=memcheck --leak-check=yes bin/release/goose_ping lo

release-test: 
	sudo bin/release/goose_ping lo
