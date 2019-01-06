.PHONY : coverage bench clean all doc test
all:
	dune build

doc:
	dune build @doc

test:
	dune runtest

clean:
	dune clean

COVERAGE=_build/default/_coverage
coverage :
	find . -name 'bisect*.out' | xargs rm -f
	BISECT_ENABLE=yes dune runtest --no-buffer -j 1 --force
	@bisect-ppx-report \
	    -I _build/default/ -html $(COVERAGE)/ \
	    -text - -summary-only \
	    _build/default/test/*.out
	@echo See $(COVERAGE)/index.html

bench:
	dune build @runbench
