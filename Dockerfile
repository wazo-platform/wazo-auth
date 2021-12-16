FROM python:3.7-slim-buster AS compile-image
LABEL maintainer="Wazo Maintainers <dev@wazo.community>"

RUN python -m venv /opt/venv
# Activate virtual env
ENV PATH="/opt/venv/bin:$PATH"

RUN apt-get -q update
RUN apt-get -yq install --no-install-recommends gcc libldap2-dev libsasl2-dev

COPY requirements.txt /usr/src/wazo-auth/
WORKDIR /usr/src/wazo-auth
RUN pip install -r requirements.txt

COPY setup.py /usr/src/wazo-auth/
COPY wazo_auth /usr/src/wazo-auth/wazo_auth
RUN python setup.py install

FROM python:3.7-slim-buster AS build-image
COPY --from=compile-image /opt/venv /opt/venv

COPY ./etc/wazo-auth /etc/wazo-auth
COPY ./templates /var/lib/wazo-auth/templates
RUN true \
    && adduser --quiet --system --group --home /var/lib/wazo-auth wazo-auth \
    && apt-get -q update \
    && apt-get -yq install --no-install-recommends libldap2-dev libsasl2-dev \
    && mkdir -p /etc/wazo-auth/conf.d \
    && mkdir -p /etc/wazo-auth/templates.d \
    && install -o wazo-auth -g wazo-auth /dev/null /var/log/wazo-auth.log \
    && rm -rf /var/lib/apt/lists/*

EXPOSE 9497

# Activate virtual env
ENV PATH="/opt/venv/bin:$PATH"
CMD ["wazo-auth", "--db-upgrade-on-startup"]
