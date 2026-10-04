# Generated from contracts/dss/kafka_dependency_lock.json; do not edit by hand.
FROM scratch AS security-inputs
ADD --checksum=sha256:9c82c86f051f3372445ecdbae5068ccc39dbc423ba8f779eaa84549fef1cfc77 https://dl-cdn.alpinelinux.org/alpine/v3.23/main/x86_64/libcrypto3-3.5.9-r0.apk /apks/libcrypto3-3.5.9-r0.apk
ADD --checksum=sha256:b5ad11f5955b3b7ddfd8c32e8c1fdd79878d208bb4dfa9bbd8f35ddc59187242 https://dl-cdn.alpinelinux.org/alpine/v3.23/main/x86_64/libssl3-3.5.9-r0.apk /apks/libssl3-3.5.9-r0.apk
ADD --checksum=sha256:80332be2dcd7a9a0408a1eeca8efd4b66adf8f79d1e99d7022d3be4a34433c4a https://dl-cdn.alpinelinux.org/alpine/v3.23/main/x86_64/openssl-3.5.9-r0.apk /apks/openssl-3.5.9-r0.apk
ADD --checksum=sha256:5216046085b92da88a6b107dbbb558f69d49c347a6335291fcf199ebd1670a8f https://dl-cdn.alpinelinux.org/alpine/v3.23/main/x86_64/libexpat-2.8.5-r0.apk /apks/libexpat-2.8.5-r0.apk
ADD --checksum=sha256:414be12c879052f4614a42a10fc12af67a88ba49e8e1e33f78cd9ddbbdb13fee https://dl-cdn.alpinelinux.org/alpine/v3.23/main/x86_64/sqlite-libs-3.53.4-r0.apk /apks/sqlite-libs-3.53.4-r0.apk
ADD --checksum=sha256:8c5623b98f32d5f7e1287ff61ed50e08ab7b11381e991fff89327faabba42261 https://repo.maven.apache.org/maven2/com/fasterxml/jackson/core/jackson-core/2.21.7/jackson-core-2.21.7.jar /jars/jackson-core-2.21.7.jar
ADD --checksum=sha256:1290c2795e93e8a6861a6c4d9ff0d844d32f5ea178362cb2721edf5561e828b1 https://repo.maven.apache.org/maven2/com/fasterxml/jackson/core/jackson-databind/2.21.7/jackson-databind-2.21.7.jar /jars/jackson-databind-2.21.7.jar
ADD --checksum=sha256:df2b3e6a194181dc067b7211d750926b4ae9e4f3c892a0005b8219a9b59be681 https://repo.maven.apache.org/maven2/com/fasterxml/jackson/dataformat/jackson-dataformat-yaml/2.21.7/jackson-dataformat-yaml-2.21.7.jar /jars/jackson-dataformat-yaml-2.21.7.jar
ADD --checksum=sha256:588050148497158cabdc05c0ae3a7e123194a486b8c62745778fc6239f9b085e https://repo.maven.apache.org/maven2/com/fasterxml/jackson/dataformat/jackson-dataformat-csv/2.21.7/jackson-dataformat-csv-2.21.7.jar /jars/jackson-dataformat-csv-2.21.7.jar
ADD --checksum=sha256:202b61a95e735d01ae03e411b8f6ae1245bbf19c87d4746c0204579f5c2e456b https://repo.maven.apache.org/maven2/com/fasterxml/jackson/jakarta/rs/jackson-jakarta-rs-base/2.21.7/jackson-jakarta-rs-base-2.21.7.jar /jars/jackson-jakarta-rs-base-2.21.7.jar
ADD --checksum=sha256:32473ee172e0c181ba63688ee4a94349de77de05bd4279d0846a9515a56bb0fe https://repo.maven.apache.org/maven2/com/fasterxml/jackson/jakarta/rs/jackson-jakarta-rs-json-provider/2.21.7/jackson-jakarta-rs-json-provider-2.21.7.jar /jars/jackson-jakarta-rs-json-provider-2.21.7.jar
ADD --checksum=sha256:76054ca6e252e7142fec9c0e9a146bd8c43cde13dddf2d1cdaecd9db981c2ddc https://repo.maven.apache.org/maven2/com/fasterxml/jackson/module/jackson-module-jakarta-xmlbind-annotations/2.21.7/jackson-module-jakarta-xmlbind-annotations-2.21.7.jar /jars/jackson-module-jakarta-xmlbind-annotations-2.21.7.jar
ADD --checksum=sha256:b41fb816cbaa5f2393136cf1c525e0d9a9f9bcea14207a09e8e703df53351596 https://repo.maven.apache.org/maven2/com/fasterxml/jackson/module/jackson-module-blackbird/2.21.7/jackson-module-blackbird-2.21.7.jar /jars/jackson-module-blackbird-2.21.7.jar
ADD --checksum=sha256:b8f62f98363ed9aa259b3a479a64fcbe7e081158a8bec6733972e900d12f4e47 https://repo.maven.apache.org/maven2/com/fasterxml/jackson/datatype/jackson-datatype-jdk8/2.21.7/jackson-datatype-jdk8-2.21.7.jar /jars/jackson-datatype-jdk8-2.21.7.jar
ADD --checksum=sha256:fb685c8d9fcf49139e9692c07da2ad6e0997252344081cdc4ff83cb423d67546 https://repo.maven.apache.org/maven2/org/jline/jline/3.30.15/jline-3.30.15.jar /jars/jline-3.30.15.jar
ADD --checksum=sha256:5b6dc693b9e3d87d309027a5f506b57225b6450444a3f276d9089f2c663cbcc4 https://repo.maven.apache.org/maven2/org/eclipse/jetty/jetty-session/12.0.36/jetty-session-12.0.36.jar /jars/jetty-session-12.0.36.jar
ADD --checksum=sha256:e16c145dd761168133d1505b6f7cf05343f5e3e3ff03333757c8a6312896ab48 https://repo.maven.apache.org/maven2/org/eclipse/jetty/jetty-util/12.0.36/jetty-util-12.0.36.jar /jars/jetty-util-12.0.36.jar
ADD --checksum=sha256:1e188b18e8ff6b60ca743e9c9cc39c35f8b6b1b6a7dc07cbdd06800672a1ee02 https://repo.maven.apache.org/maven2/org/eclipse/jetty/jetty-client/12.0.36/jetty-client-12.0.36.jar /jars/jetty-client-12.0.36.jar
ADD --checksum=sha256:6b0e03b545fa49fc82cf3149dafb3849e6e0827b3756c31b0e1f5324d86816d2 https://repo.maven.apache.org/maven2/org/eclipse/jetty/jetty-alpn-client/12.0.36/jetty-alpn-client-12.0.36.jar /jars/jetty-alpn-client-12.0.36.jar
ADD --checksum=sha256:e6fb70974291312c58ac84d8bf28c909d1800d1b3104020e7cd4db77391f9fb2 https://repo.maven.apache.org/maven2/org/eclipse/jetty/jetty-security/12.0.36/jetty-security-12.0.36.jar /jars/jetty-security-12.0.36.jar
ADD --checksum=sha256:2b5c6ee1303aa979b99afb27e3c602096c344e06da9bdc0057938d1c47f8f1f2 https://repo.maven.apache.org/maven2/org/eclipse/jetty/jetty-http/12.0.36/jetty-http-12.0.36.jar /jars/jetty-http-12.0.36.jar
ADD --checksum=sha256:f0eb8d1e71d67d0f937c45752546cf479ba55ad3135cf600d3bf723f52cd53fe https://repo.maven.apache.org/maven2/org/eclipse/jetty/jetty-server/12.0.36/jetty-server-12.0.36.jar /jars/jetty-server-12.0.36.jar
ADD --checksum=sha256:b191d45e3c48711cc784d509a8dec50112816af392b2b7c76d9e42324b5064da https://repo.maven.apache.org/maven2/org/eclipse/jetty/jetty-io/12.0.36/jetty-io-12.0.36.jar /jars/jetty-io-12.0.36.jar
ADD --checksum=sha256:e4bc43fbe7ddb1f7658a935b9ad0329d9cf4eae446533bfed7822e6183fe933e https://repo.maven.apache.org/maven2/org/eclipse/jetty/ee10/jetty-ee10-servlets/12.0.36/jetty-ee10-servlets-12.0.36.jar /jars/jetty-ee10-servlets-12.0.36.jar
ADD --checksum=sha256:64d42fc2e1c3fd6b7e7a77c1165626bce3a52ef3ed89a7cf00163d11b42201c8 https://repo.maven.apache.org/maven2/org/eclipse/jetty/ee10/jetty-ee10-servlet/12.0.36/jetty-ee10-servlet-12.0.36.jar /jars/jetty-ee10-servlet-12.0.36.jar

FROM apache/kafka:4.3.1@sha256:77e3df9054047a88b520d0cc46e16696d3b22022e1d580aeccd2632df6532837 AS secured-runtime
ARG SPELL_PACKAGE_VERSION=0.19.0
LABEL org.openbexi.spell.component="kafka" \
      org.openbexi.spell.scope="local-satellite-simulator" \
      org.openbexi.spell.package.version="${SPELL_PACKAGE_VERSION}"
USER root
COPY --from=security-inputs /apks/ /tmp/security-updates/
RUN apk add --no-cache --no-network /tmp/security-updates/*.apk \
    && rm -f /tmp/security-updates/*.apk \
    && rm -f /opt/kafka/libs/jackson-core-2.21.2.jar \
        /opt/kafka/libs/jackson-databind-2.21.2.jar \
        /opt/kafka/libs/jackson-dataformat-yaml-2.21.2.jar \
        /opt/kafka/libs/jackson-dataformat-csv-2.21.2.jar \
        /opt/kafka/libs/jackson-jakarta-rs-base-2.21.2.jar \
        /opt/kafka/libs/jackson-jakarta-rs-json-provider-2.21.2.jar \
        /opt/kafka/libs/jackson-module-jakarta-xmlbind-annotations-2.21.2.jar \
        /opt/kafka/libs/jackson-module-blackbird-2.21.2.jar \
        /opt/kafka/libs/jackson-datatype-jdk8-2.21.2.jar \
        /opt/kafka/libs/jline-3.30.4.jar \
        /opt/kafka/libs/jetty-session-12.0.34.jar \
        /opt/kafka/libs/jetty-util-12.0.34.jar \
        /opt/kafka/libs/jetty-client-12.0.34.jar \
        /opt/kafka/libs/jetty-alpn-client-12.0.34.jar \
        /opt/kafka/libs/jetty-security-12.0.34.jar \
        /opt/kafka/libs/jetty-http-12.0.34.jar \
        /opt/kafka/libs/jetty-server-12.0.34.jar \
        /opt/kafka/libs/jetty-io-12.0.34.jar \
        /opt/kafka/libs/jetty-ee10-servlets-12.0.34.jar \
        /opt/kafka/libs/jetty-ee10-servlet-12.0.34.jar \
    && mkdir -p /var/lib/kafka/data /usr/local/share/openbexi \
    && chown 1000:1000 /var/lib/kafka/data
COPY --chmod=0644 --from=security-inputs /jars/ /opt/kafka/libs/
COPY contracts/dss/kafka_dependency_lock.json /usr/local/share/openbexi/kafka_dependency_lock.json

# Copy only the secured filesystem: deleted vulnerable artifacts are absent from all delivered layers.
FROM scratch
COPY --from=secured-runtime / /
ARG SPELL_PACKAGE_VERSION=0.19.0
LABEL org.openbexi.spell.component="kafka" \
      org.openbexi.spell.scope="local-satellite-simulator" \
      org.openbexi.spell.package.version="${SPELL_PACKAGE_VERSION}"
ENV PATH="/opt/java/openjdk/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
    JAVA_HOME="/opt/java/openjdk" LANG="en_US.UTF-8" LANGUAGE="en_US:en" \
    LC_ALL="en_US.UTF-8" JAVA_VERSION="jdk-21.0.11+10"
USER 1000:1000
ENTRYPOINT ["/__cacert_entrypoint.sh"]
CMD ["/etc/kafka/docker/run"]
