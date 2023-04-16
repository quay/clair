FROM node:slim AS app

RUN apt-get update

COPY . /opt/quay

WORKDIR /opt/quay

RUN npm install

CMD node app.js