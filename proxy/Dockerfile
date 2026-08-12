FROM node:22-alpine@sha256:16e22a550f3863206a3f701448c45f7912c6896a62de43add43bb9c86130c3e2 AS frontend-builder

WORKDIR /src/frontend
RUN chown node:node /src/frontend
USER node
COPY --chown=node:node frontend/package.json frontend/package-lock.json ./
RUN npm ci --ignore-scripts --no-audit
COPY --chown=node:node frontend/ ./
RUN npm run build

FROM node:22-alpine@sha256:16e22a550f3863206a3f701448c45f7912c6896a62de43add43bb9c86130c3e2 AS frontend-build

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

RUN apk del --no-network curl libcurl \
    && apk add --no-cache --upgrade \
    "libcrypto3=3.5.7-r0" \
    "libssl3=3.5.7-r0"
COPY proxy/nginx.conf /etc/nginx/nginx.conf
COPY proxy/security_headers.conf /etc/nginx/security_headers.conf
COPY --from=frontend-build /src/frontend/dist /usr/share/nginx/html

USER 101:101
EXPOSE 8080
