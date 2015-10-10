FROM python:2.7
MAINTAINER Sylvain Boily "sboily@avencall.com"

RUN apt-get -yq update \
   && apt-get -yqq dist-upgrade \
   && apt-get -yq autoremove \
   && apt-get install libldap2-dev \
                      libsasl2-dev

# Install
ADD . /usr/src/xivo-auth
WORKDIR /usr/src/xivo-auth
RUN pip install --upgrade pip
RUN pip install -r requirements.txt
RUN python setup.py install

#Configure environment
RUN touch /var/log/xivo-auth.log
RUN mkdir -p /etc/xivo-auth/{conf.d,services.d}
RUN cp /usr/src/xivo-auth/etc/xivo-auth/*.yml /etc/xivo-auth/
RUN install -d -o www-data -g www-data /var/run/xivo-auth/

EXPOSE 9497

CMD xivo-auth -fd --user www-data
