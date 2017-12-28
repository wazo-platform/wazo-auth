FROM python:2.7.13
MAINTAINER Wazo Maintainers <dev@wazo.community>

ADD . /usr/src/wazo-auth
ADD ./contribs/docker/certs /usr/share/xivo-certs
WORKDIR /usr/src/wazo-auth

RUN apt-get update \
    && apt-get -yq install libldap2-dev libsasl2-dev \
    && pip install -r requirements.txt \
    && python setup.py install \
    && touch /var/log/wazo-auth.log \
    && mkdir -p /etc/wazo-auth/conf.d \
    && cp /usr/src/wazo-auth/etc/wazo-auth/*.yml /etc/wazo-auth/ \
    && adduser --quiet --system --group --home /var/lib/wazo-auth wazo-auth \
    && install -d -o wazo-auth -g wazo-auth /var/run/wazo-auth/ \
    && true

EXPOSE 9497

CMD ["wazo-auth", "-fd"]
