# Makefile for generating RADIUS certificates in certs directory

.PHONY: ca.pem server.pem dh

ca.pem:
	@if [ ! -f ca.pem ]; then \
		openssl req -new -x509 -keyout ca.key -out ca.pem -days 3650 -nodes \
			-subj "/C=US/ST=State/L=City/O=School/CN=School CA"; \
	fi

server.pem: ca.pem
	@if [ ! -f server.pem ]; then \
		openssl req -new -keyout server.key -out server.csr -nodes \
			-subj "/C=US/ST=State/L=City/O=School/CN=radius.school.local"; \
		openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key \
			-out server.pem -days 3650 -CAcreateserial; \
		cat server.key server.pem > server.pem.tmp; \
		mv server.pem.tmp server.pem; \
		rm server.csr server.key; \
	fi

dh:
	@if [ ! -f dh ]; then \
		openssl dhparam -out dh 2048; \
	fi

clean:
	rm -f *.pem *.key *.csr *.srl dh
