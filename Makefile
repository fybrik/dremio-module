include Makefile.env
include hack/make-rules/tools.mk
include hack/make-rules/helm.mk

export DOCKER_USERNAME ?= tomersolomon1
export DOCKER_PASSWORD ?= 
export DOCKER_HOSTNAME ?= ghcr.io
export DOCKER_NAMESPACE ?= tomersolomon1
export DOCKER_TAGNAME ?= main

DOCKER_FILE_REGISTER ?= Dockerfile
DOCKER_FILE_CLEAN ?= Dockerfileclean
DOCKER_CONTEXT ?= .
DOCKER_NAME_REGISTER ?= dremio-module-register
DOCKER_NAME_CLEAN ?= dremio-module-clean

APP_IMG_REGISTER ?= ${DOCKER_HOSTNAME}/${DOCKER_NAMESPACE}/${DOCKER_NAME_REGISTER}:${DOCKER_TAGNAME}
APP_IMG_CLEAN ?= ${DOCKER_HOSTNAME}/${DOCKER_NAMESPACE}/${DOCKER_NAME_CLEAN}:${DOCKER_TAGNAME}


.PHONY: docker-login
docker-login:
ifneq (${DOCKER_PASSWORD},)
	@docker login \
		--username ${DOCKER_USERNAME} \
		--password ${DOCKER_PASSWORD} ${DOCKER_HOSTNAME}
endif

.PHONY: docker-all
docker-all: docker-build docker-push

##############
.PHONY: docker-build
docker-build: docker-build-register docker-build-clean

.PHONY: docker-build-register
docker-build-register:
	docker build $(DOCKER_CONTEXT) -t ${APP_IMG_REGISTER} -f $(DOCKER_FILE_REGISTER)

.PHONY: docker-build-clean
docker-build-clean:
	docker build $(DOCKER_CONTEXT) -t ${APP_IMG_CLEAN} -f $(DOCKER_FILE_CLEAN)

##############
.PHONY: docker-push
docker-push: docker-push-register docker-push-clean

.PHONY: docker-push-register
docker-push-register: docker-login
	docker push ${APP_IMG_REGISTER}

.PHONY: docker-push-clean
docker-push-clean: docker-login
	docker push ${APP_IMG_CLEAN}

##############
.PHONY: docker-rmi
docker-rmi: docker-rmi-register docker-rmi-clean

.PHONY: docker-rmi-register
docker-rmi:
	docker rmi ${APP_IMG_REGISTER} || true

.PHONY: docker-rmi-clean
docker-rmi-clean:
	docker rmi ${APP_IMG_CLEAN} || true
