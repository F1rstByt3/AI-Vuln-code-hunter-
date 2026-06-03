# Multi-stage production build -> static files served by nginx.
FROM node:20-alpine AS build
WORKDIR /web
COPY package*.json ./
RUN npm install
COPY . .
ARG VITE_API_BASE_URL=/
ENV VITE_API_BASE_URL=$VITE_API_BASE_URL
RUN npm run build

FROM nginx:alpine
COPY --from=build /web/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
