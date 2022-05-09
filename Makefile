include Makefile.env

export DOCKER_USERNAME ?= mohammad-nassar10
export DOCKER_PASSWORD ?= 
export DOCKER_HOSTNAME ?= ghcr.io
export DOCKER_NAMESPACE ?= mohammad-nassar10
export DOCKER_TAGNAME ?= main

DOCKER_FILE ?= Dockerfile
DOCKER_CONTEXT ?= .
DOCKER_NAME ?= dremio-module

APP_IMG ?= ${DOCKER_HOSTNAME}/${DOCKER_NAMESPACE}/${DOCKER_NAME}:${DOCKER_TAGNAME}

.PHONY: docker-all
docker-all: docker-build docker-push

.PHONY: docker-build
docker-build:
	docker build $(DOCKER_CONTEXT) -t ${APP_IMG} -f $(DOCKER_FILE)

.PHONY: docker-push
docker-push:
ifneq (${DOCKER_PASSWORD},)
	@docker login \
		--username ${DOCKER_USERNAME} \
		--password ${DOCKER_PASSWORD} ${DOCKER_HOSTNAME}
endif
	docker push ${APP_IMG}

.PHONY: docker-rmi
docker-rmi:
	docker rmi ${APP_IMG} || true


include hack/make-rules/tools.mk
include hack/make-rules/helm.mk

