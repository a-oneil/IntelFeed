FROM node:22-alpine AS build

WORKDIR /app

RUN npm i -g pnpm@10

COPY package.json pnpm-lock.yaml* ./
RUN pnpm install --frozen-lockfile 2>/dev/null || pnpm install

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
FROM nginx:alpine

COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
