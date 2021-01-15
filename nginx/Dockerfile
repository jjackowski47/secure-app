FROM nginx

RUN rm /etc/nginx/conf.d/default.conf

COPY nginx.conf /etc/nginx/conf.d/

COPY secure.app.crt /etc/nginx/secure.app.crt
COPY secure.app.key /etc/nginx/secure.app.key
COPY secure.app.pass /etc/keys/secure.app.pass