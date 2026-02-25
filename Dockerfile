FROM ubuntu:24.04 AS build
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
	build-essential autoconf automake flex bison python3-docutils libtool pkg-config ca-certificates git wget \
	gcc g++ make pkg-config libssl-dev zlib1g-dev liblz4-dev libzstd-dev libcurl4-gnutls-dev \
	libgnutls28-dev libsystemd-dev libestr-dev uuid-dev libgcrypt20-dev librelp-dev libyaml-dev && rm -rf /var/lib/apt/lists/*

ENV PKG_CONFIG_PATH=/usr/local/lib/pkgconfig

# build helper libs (libfastjson) which may not be packaged
RUN mkdir -p /helper-projects && cd /helper-projects && \
	git clone https://github.com/rsyslog/libfastjson.git && \
	cd libfastjson && autoreconf -fi && \
	./configure --prefix=/usr --libdir=/usr/lib/x86_64-linux-gnu --includedir=/usr/include && \
	make -j$(nproc) && make install && rm -rf /helper-projects/libfastjson

	
WORKDIR /src
COPY . /src
RUN ./autogen.sh && ./configure --prefix=/usr --enable-omazuredce && make -j$(nproc) && make install DESTDIR=/out

# runtime image: keep it Ubuntu for library compatibility
FROM ubuntu:24.04 AS runtime
RUN apt-get update && apt-get install -y ca-certificates libsystemd0 libssl3 libyaml-0-2 libestr0 libcurl3t64-gnutls && rm -rf /var/lib/apt/lists/*
RUN groupadd -r syslog && useradd -r -g syslog syslog
RUN mkdir -p /var/log && chown -R syslog:syslog /var/log
COPY --from=build /out/usr/sbin/rsyslogd /usr/sbin/rsyslogd
COPY --from=build /out/usr/lib/rsyslog /usr/lib/rsyslog
COPY --from=build /usr/lib/x86_64-linux-gnu/libfastjson.so* /usr/lib/x86_64-linux-gnu/
COPY rsyslog.conf.sample /etc/rsyslog.conf
#EXPOSE 514/udp 514/tcp
CMD ["/usr/sbin/rsyslogd","-n"]
