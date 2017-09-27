FROM python:2.7.9
MAINTAINER Wazo Maintainers <dev.wazo@gmail.com>

ADD . /usr/src/xivo-auth
ADD ./contribs/docker/certs /usr/share/xivo-certs
WORKDIR /usr/src/xivo-auth

RUN apt-get update \
    && apt-get -yq install libldap2-dev libsasl2-dev \
    && pip install -r requirements.txt \
    && python setup.py install \
    && touch /var/log/xivo-auth.log \
    && mkdir -p /etc/xivo-auth/conf.d \
    && cp /usr/src/xivo-auth/etc/xivo-auth/*.yml /etc/xivo-auth/ \
    && install -d -o www-data -g www-data /var/run/wazo-auth/

EXPOSE 9497

CMD ["xivo-auth", "-fd", "--user", "www-data"]
