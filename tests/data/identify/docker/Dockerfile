FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        clang \
        file \
        llvm \
        make \
        python3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work

CMD ["bash"]
