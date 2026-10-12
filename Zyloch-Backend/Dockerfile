FROM node:20-alpine

# Install nodemon globally for development
RUN npm install -g nodemon

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install all dependencies (including dev dependencies)
RUN npm install

# Copy source code
COPY . .

# Expose port
EXPOSE 8000

EXPOSE 3000
ENV HOST=0.0.0.0

CMD ["npm", "run", "start", "--", "-H", "0.0.0.0", "-p", "5000"]
