nitro-cli terminate-enclave --all
docker build -t test -f Dockerfile  .
nitro-cli build-enclave --docker-uri test:latest --output-file test.eif
nitro-cli run-enclave --cpu-count 2 --memory 3000 --enclave-cid 5 --eif-path test.eif
#nitro-cli console --enclave-name test