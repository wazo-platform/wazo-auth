FROM python:2.7.9
MAINTAINER Wazo Maintainers <dev@wazo.community>

ADD . /usr/src/xivo-auth
ADD ./contribs/docker/certs /usr/share/xivo-certs
WORKDIR /usr/src/xivo-auth

RUN apt-get update \
    && apt-get -yq install libldap2-dev libsasl2-dev \
    && pip install -r requirements.txt \
    && python setup.py install \
    && touch /var/log/wazo-auth.log \
    && mkdir -p /etc/wazo-auth/conf.d \
    && cp /usr/src/xivo-auth/etc/wazo-auth/*.yml /etc/wazo-auth/ \
    && adduser --quiet --system --group --no-create-home --home /var/lib/wazo-auth wazo-auth \
    && install -d -o wazo-auth -g wazo-auth /var/run/wazo-auth/ \
    && true

EXPOSE 9497

CMD ["xivo-auth", "-fd"]
