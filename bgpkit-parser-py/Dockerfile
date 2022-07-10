FROM messense/manylinux2014-cross:x86_64

RUN apt update && apt install cargo libssl-dev pkg-config -y
RUN python3 -m pip install maturin

WORKDIR /io
ENTRYPOINT ["/usr/local/bin/maturin"]