FROM alpine:3.20 AS builder
RUN apk add --no-cache g++ libpcap-dev openssl-dev openssl-libs-static zstd-dev zstd-static

FROM builder AS nt
COPY src/* /build/
RUN cd /build && g++ *.cpp -o nt -pthread -O2 -flto -fwhole-program -static -lzstd -lcrypto -lpcap -Wno-deprecated-declarations

FROM crystallang/crystal:1.14-alpine AS crystal
COPY import/vicmet.cr /build/
RUN cd /build && crystal build vicmet.cr --release --static -o import

FROM scratch
COPY --from=nt /build/nt /nt
COPY --from=crystal /build/import /import
