FROM python:2.7
MAINTAINER Sylvain Boily "sboily@avencall.com"

RUN apt-get -yq update \
   && apt-get -yqq dist-upgrade \
   && apt-get -yq autoremove

ADD . /usr/src/xivo-auth
WORKDIR /usr/src/xivo-auth
RUN pip install --upgrade pip
RUN pip install -r requirements.txt
RUN python setup.py install
RUN mkdir /etc/xivo-auth/conf.d
RUN mkdir -p /var/run/xivo-auth
RUN chown -R www-data:www-data /var/run/xivo-auth

EXPOSE 9497

CMD xivo-auth -fd --user www-data
