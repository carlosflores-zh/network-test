Configuration?
- I followed this steps to configure EC2 instance, install dependencies, compile and configure KMS
  - https://github.com/aws/aws-nitro-enclaves-sdk-c/blob/main/docs/kmstool.md#kmstool-enclave-cli

How to run?
- I copy files to EC2 instance with (update your paths):
  - `make move`
- Start EC2 proxy with:
  - `make run-proxy`
  - If it fails sometimes you have to kill a previous instance with kill, and unlink socket with: `sudo unlink /tmp/network.sock`
- In another console start run enclave app with:
  - `make run-enclave`
- In another console, add rules to proxy to expose enclave-api:
  - `make add-rules`
- test api with:
  - `wget http://localhost:8443/hello-world`
  - You will get a code 200, and Hello World! as response
  - In the console where you run the enclave app, you will see the request to the json public api
- get attestation doc:
  - wget  http://localhost:8443/enclave/attestation?nonce=2133213123123123121231231231231267845231