include Makefile.env

export DOCKER_USERNAME ?= mohammad-nassar10
export DOCKER_PASSWORD ?= 
export DOCKER_HOSTNAME ?= ghcr.io
export DOCKER_NAMESPACE ?= mohammad-nassar10
export DOCKER_TAGNAME ?= main

DOCKER_FILE ?= Dockerfile
DOCKER_FILE_CLEAN ?= Dockerfileclean
DOCKER_CONTEXT ?= .
DOCKER_NAME ?= dremio-module
DOCKER_NAME_CLEAN ?= dremio-module-clean

APP_IMG ?= ${DOCKER_HOSTNAME}/${DOCKER_NAMESPACE}/${DOCKER_NAME}:${DOCKER_TAGNAME}
APP_IMG_CLEAN ?= ${DOCKER_HOSTNAME}/${DOCKER_NAMESPACE}/${DOCKER_NAME_CLEAN}:${DOCKER_TAGNAME}

.PHONY: docker-all
docker-all: docker-build docker-push

.PHONY: docker-build
docker-build:
	docker build $(DOCKER_CONTEXT) -t ${APP_IMG} -f $(DOCKER_FILE)

.PHONY: docker-build-clean
docker-build-clean:
	docker build $(DOCKER_CONTEXT) -t ${APP_IMG_CLEAN} -f $(DOCKER_FILE_CLEAN)

.PHONY: docker-push
docker-push:
ifneq (${DOCKER_PASSWORD},)
	@docker login \
		--username ${DOCKER_USERNAME} \
		--password ${DOCKER_PASSWORD} ${DOCKER_HOSTNAME}
endif
	docker push ${APP_IMG}

.PHONY: docker-push-clean
docker-push-clean:
ifneq (${DOCKER_PASSWORD},)
	@docker login \
		--username ${DOCKER_USERNAME} \
		--password ${DOCKER_PASSWORD} ${DOCKER_HOSTNAME}
endif
	docker push ${APP_IMG_CLEAN}

.PHONY: docker-rmi
docker-rmi:
	docker rmi ${APP_IMG} || true

.PHONY: docker-rmi-clean
docker-rmi-clean:
	docker rmi ${APP_IMG_CLEAN} || true


include hack/make-rules/tools.mk
include hack/make-rules/helm.mk
