ARG debian_snapshot=buster-20201012

FROM debian/snapshot:${debian_snapshot}

RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y apt-utils && \
    apt-get install -y build-essential && \
    apt-get install -y git && \
    apt-get install -y vim && \
    apt-get install -y cmake && \
    apt-get install -y protobuf-compiler && \
    apt-get install -y libzmq3-dev && \
    apt-get install -y librocksdb-dev && \
    apt-get install -y libgflags-dev

#install cmake v3.20.4
ADD https://cmake.org/files/v3.20/cmake-3.20.4-linux-x86_64.sh /cmake-3.20.4-linux-x86_64.sh
RUN mkdir /opt/cmake
RUN sh /cmake-3.20.4-linux-x86_64.sh --prefix=/opt/cmake --skip-license
RUN ln -s /opt/cmake/bin/cmake /usr/local/bin/cmake
RUN cmake --version

CMD ["/bin/bash"]
