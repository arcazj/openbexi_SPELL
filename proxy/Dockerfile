FROM node:22-alpine@sha256:16e22a550f3863206a3f701448c45f7912c6896a62de43add43bb9c86130c3e2 AS frontend-build

WORKDIR /src/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --ignore-scripts --no-audit
COPY frontend/ ./
RUN npm run build

FROM nginx:1.29-alpine@sha256:5616878291a2eed594aee8db4dade5878cf7edcb475e59193904b198d9b830de

COPY proxy/nginx.conf /etc/nginx/nginx.conf
COPY proxy/security_headers.conf /etc/nginx/security_headers.conf
COPY --from=frontend-build /src/frontend/dist /usr/share/nginx/html

USER 101:101
EXPOSE 8080
