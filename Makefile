SECRETS := ./.env

up.json: up.json.in
	test -f $(SECRETS) && . $(SECRETS) && envsubst < $< > $@

ls:
	aws --profile uneet-dev s3 ls s3://uneet-checkout-test/

clean:
	rm up.json
