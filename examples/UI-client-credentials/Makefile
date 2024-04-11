current_dir := $(shell pwd)

build:
	docker image rm -f firecrest-live
	docker build -f ./docker/Dockerfile -t firecrest-live .
run:
	docker run --rm -p 9090:9090 -v ${current_dir}/log:/var/log  --name firecrest-live firecrest-live
stop:
	docker stop firecrest-live