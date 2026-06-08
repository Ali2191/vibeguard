FROM node:latest
WORKDIR /app
COPY . .
RUN npm install
RUN groupadd -r app && useradd -r -g app app
RUN chown -R app:app /app
USER app
CMD ["node", "app.js"]