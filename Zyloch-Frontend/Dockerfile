
FROM node:20-alpine

WORKDIR /app

COPY package*.json ./

RUN npm ci

COPY . .

RUN chmod +x node_modules/.bin/next

# Placeholder defaults are baked into the bundle at build time.
# The docker-entrypoint.sh replaces these with real values from
# Kubernetes Secrets before the app starts.
ARG NEXT_PUBLIC_API_URL=__NEXT_PUBLIC_API_URL__
ARG NEXT_PUBLIC_GITHUB_APP_URL=__NEXT_PUBLIC_GITHUB_APP_URL__
ARG NEXT_PUBLIC_FRONTEND_URL=__NEXT_PUBLIC_FRONTEND_URL__

ENV NEXT_PUBLIC_API_URL=$NEXT_PUBLIC_API_URL
ENV NEXT_PUBLIC_GITHUB_APP_URL=$NEXT_PUBLIC_GITHUB_APP_URL
ENV NEXT_PUBLIC_FRONTEND_URL=$NEXT_PUBLIC_FRONTEND_URL


RUN npm run build

RUN npm prune --production

COPY docker-entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 3000
ENV HOST=0.0.0.0
ENTRYPOINT ["/entrypoint.sh"]
CMD ["npm", "run", "start", "--", "-H", "0.0.0.0", "-p", "3000"]