build:
	docker build -t aws-creds .
	docker run --rm aws-creds cat /go/bin/aws-creds > aws-creds
	chmod u+x aws-creds

clean:
	rm aws-creds

.PHONY: clean
