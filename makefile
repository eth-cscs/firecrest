setup:
	$(MAKE) setup -C testbed

DOCKERNET = $(shell docker network ls | grep cscs-api)

build-network:
	$(shell if ! docker network ls | grep -q cscs-api; then docker network create --subnet=192.168.200.0/26 cscs-api; fi)

build: setup build-network
	$(MAKE) build -C containers/Jobs
	$(MAKE) build -C containers/Barbican
	$(MAKE) build -C containers/Certificator
	$(MAKE) build -C containers/Cluster
	$(MAKE) build -C containers/Kong
	$(MAKE) build -C containers/Queue
	$(MAKE) build -C containers/Storage


clean-all:
	$(MAKE) clean-keys -C testbed
	$(MAKE) clean -C containers/Jobs
	$(MAKE) clean -C containers/Barbican
	$(MAKE) clean -C containers/Certificator
	$(MAKE) clean -C containers/Cluster
	$(MAKE) clean -C containers/Kong
	$(MAKE) clean -C containers/Queue
	$(MAKE) clean -C containers/Storage

