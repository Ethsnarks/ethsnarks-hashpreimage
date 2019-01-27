CLI = .build/hashpreimage_cli
KEY_PREFIX = .keys/hashpreimage
PROVING_KEY = $(KEY_PREFIX).pk.raw
VERIFYING_KEY = $(KEY_PREFIX).vk.json
GIT ?= git

all: $(CLI) test

$(CLI): .build
	$(MAKE) -C $(dir $@)

.build:
	mkdir -p $@
	cd $@ && cmake ../circuit/ || rm -rf ../$@

debug:
	mkdir -p .build && cd .build && cmake -DCMAKE_BUILD_TYPE=Debug ../circuit/

release:
	mkdir -p .build && cd .build && cmake -DCMAKE_BUILD_TYPE=Release ../circuit/

performance:
	mkdir -p .build && cd .build && cmake -DCMAKE_BUILD_TYPE=Release -DPERFORMANCE=1 ../circuit/

git-submodules:
	$(GIT) submodule update --init --recursive

git-pull:
	$(GIT) pull --recurse-submodules
	$(GIT) submodule update --recursive --remote

cxx-tests:
	$(MAKE) -C .build test

clean:
	rm -rf .build

python-test:
	$(MAKE) -C python test

solidity-test:
	$(MAKE) -C solidity test

test: cxx-tests cli-tests python-test solidity-test

.keys/hashpreimage.pk.raw: $(CLI)
	mkdir -p $(dir $@)
	$(CLI) genkeys $(PROVING_KEY) $(VERIFYING_KEY)

cli-tests: $(PROVING_KEY)
	ls -lah $(PROVING_KEY)
	time $(CLI) prove $(PROVING_KEY) 0x9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a089f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 .keys/hpi.proof.json
	time $(CLI) verify $(VERIFYING_KEY) .keys/hpi.proof.json
	#time ./build/src/test/benchmark/benchmark_load_proofkey .keys/hpi.pk.raw
