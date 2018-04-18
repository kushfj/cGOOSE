debug: src
	mkdir -p ./bin/debug/
	$(MAKE) debug -C src 

release: src
	mkdir -p ./bin/release/
	$(MAKE) release -C src 

all: release


.PHONY: clean
clean:
	rm -rf ./bin/
	rm -rf ./doc/

doc: Doxyfile
	doxygen Doxyfile
