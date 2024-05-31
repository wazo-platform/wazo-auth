FROM python:3.10-alpine AS builder

RUN addgroup -S nonroot \
    && adduser -S nonroot -G nonroot

USER nonroot

WORKDIR /app

COPY requirements.txt /app
RUN pip3 install --no-cache-dir -r requirements.txt

COPY server.py /app
COPY templates /app/templates/

EXPOSE 8800

ENTRYPOINT ["python3"]
CMD ["server.py"]
