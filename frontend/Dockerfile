FROM node:26.12.1-alpine3.24 AS build

WORKDIR /app

# The exact pnpm that package.json's "packageManager" names (CI reads the same
# field). Bump the two together.
RUN npm i -g pnpm@10.31.0

# --frozen-lockfile with no fallback: if pnpm-lock.yaml and package.json
# disagree the build fails, rather than resolving a tree nobody reviewed.
COPY package.json pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile

COPY . .

ARG VITE_API_URL
ENV VITE_API_URL=${VITE_API_URL}

# Build stamp, injected by compose from scripts/ops/version.sh. Vite inlines
# VITE_* at build time, so this is baked into the bundle rather than fetched.
ARG VITE_APP_VERSION=dev
ARG VITE_GIT_SHA=""
ARG VITE_BUILD_TIME=""
ENV VITE_APP_VERSION=${VITE_APP_VERSION} VITE_GIT_SHA=${VITE_GIT_SHA} VITE_BUILD_TIME=${VITE_BUILD_TIME}

RUN pnpm build

# Serve with nginx
FROM nginx:1.31.8-alpine3.24

COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
