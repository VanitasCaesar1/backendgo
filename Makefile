clean:
	go clean
	rm -f $(APP_NAME)
	docker rmi $(DOCKER_REPO):$(VERSION) 2>/dev/null || true

build:
	go build -o $(APP_NAME) .

docker-build:
	docker build -t $(DOCKER_REPO):$(VERSION) .

.PHONY: deploy
deploy:
	ssh root@195.35.23.208 \
		"docker pull $(DOCKER_REPO):$(VERSION) && \
		docker stop $(APP_NAME) || true && \
		docker rm $(APP_NAME) || true && \
		docker run -d --name $(APP_NAME) -p 8080:8080 $(DOCKER_REPO):$(VERSION)"
