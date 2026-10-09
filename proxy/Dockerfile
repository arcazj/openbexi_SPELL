FROM scratch AS zlib-security-inputs
ADD --checksum=sha256:63aeea03c15a2f9018f81805cfc8aa926bdf5cd68921f22149c2fbb5d0ee9f47 https://dl-cdn.alpinelinux.org/alpine/v3.24/main/x86_64/zlib-1.3.2-r1.apk /alpine324/zlib-1.3.2-r1.apk
ADD --checksum=sha256:ee62e1864c235901e2aa4d1868c7ae8f7cc5d0740a98c48a2525332eb4bfda73 https://dl-cdn.alpinelinux.org/alpine/v3.23/main/x86_64/zlib-1.3.2-r1.apk /alpine323/zlib-1.3.2-r1.apk

FROM node:22-alpine@sha256:16e22a550f3863206a3f701448c45f7912c6896a62de43add43bb9c86130c3e2 AS frontend-builder

COPY --from=zlib-security-inputs /alpine324/ /tmp/zlib-security-update/
RUN apk add --no-cache --no-network /tmp/zlib-security-update/*.apk && rm -rf /tmp/zlib-security-update
RUN apk add --no-cache --upgrade libcrypto3=3.5.9-r0 libssl3=3.5.9-r0
WORKDIR /src/frontend
RUN chown node:node /src/frontend
USER node
COPY --chown=node:node frontend/package.json frontend/package-lock.json ./
RUN npm ci --ignore-scripts --no-audit
COPY --chown=node:node frontend/ ./
RUN npm run build

FROM node:22-alpine@sha256:16e22a550f3863206a3f701448c45f7912c6896a62de43add43bb9c86130c3e2 AS frontend-build

COPY --from=zlib-security-inputs /alpine324/ /tmp/zlib-security-update/
RUN apk add --no-cache --no-network /tmp/zlib-security-update/*.apk && rm -rf /tmp/zlib-security-update
RUN apk add --no-cache --upgrade libcrypto3=3.5.9-r0 libssl3=3.5.9-r0
WORKDIR /src/frontend
RUN chown node:node /src/frontend
USER node
COPY --chown=node:node frontend/package.json frontend/package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts --no-audit \
    && rm -rf "$HOME/.npm" /tmp/*
COPY --from=frontend-builder --chown=node:node /src/frontend/dist ./dist
USER root
RUN rm -rf /usr/local/lib/node_modules/npm /usr/local/bin/npm /usr/local/bin/npx
USER node

FROM nginx:1.29-alpine@sha256:5616878291a2eed594aee8db4dade5878cf7edcb475e59193904b198d9b830de

COPY --from=zlib-security-inputs /alpine323/ /tmp/zlib-security-update/
RUN apk add --no-cache --no-network /tmp/zlib-security-update/*.apk && rm -rf /tmp/zlib-security-update
RUN apk del --no-network curl libcurl nginx-module-xslt nginx-module-njs \
    nginx-module-image-filter nginx-module-geoip nginx-module-acme \
    && apk add --no-cache --upgrade \
    "libcrypto3=3.5.9-r0" \
    "libssl3=3.5.9-r0" "pcre2=10.49-r0" "xz-libs=5.8.4-r0"
COPY proxy/nginx.conf /etc/nginx/nginx.conf
COPY proxy/security_headers.conf /etc/nginx/security_headers.conf
COPY --from=frontend-build /src/frontend/dist /usr/share/nginx/html

USER 101:101
EXPOSE 8080
