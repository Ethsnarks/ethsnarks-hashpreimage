CLI = .build/x_hashpreimage_cli

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
	git submodule update --init --recursive

git-pull:
	git pull --recurse-submodules
	git submodule update --recursive --remote

clean:
	rm -rf .build

python-test:
	$(MAKE) -C python test

solidity-test:
	$(MAKE) -C solidity test

test: .keys/hashpreimage.pk.raw solidity-test python-test

.keys/hashpreimage.pk.raw: $(CLI)
	mkdir -p $(dir $@)
	$(CLI) genkeys .keys/hashpreimage.pk.raw .keys/hashpreimage.vk.json
