#!/bin/bash

#Generates a self assigned cert
#Generates cert.pem and key.pem
go run generate_cert.go -host 127.0.0.1 -ca 0
go run main.go
