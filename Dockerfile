FROM python:3.8.16-alpine3.17 as builder
WORKDIR /usr/cycode/app
COPY . ./
RUN python -m pip install --upgrade --no-cache-dir pip==22.0.4 setuptools==65.5.1 wheel==0.37.1
RUN python3 setup.py sdist bdist_wheel

FROM python:3.8.16-alpine3.17
RUN apk add git=2.38.3-r1
WORKDIR /usr/cycode/app
COPY --from=builder usr/cycode/app/dist ./
RUN pip install --no-cache-dir cycode*.whl

# Add cycode group and user, alpine way
# https://wiki.alpinelinux.org/wiki/Setting_up_a_new_user
RUN addgroup -g 5000 cycode-group
RUN adduser --home /home/cycode --uid 5001 -G cycode-group --shell /bin/sh --disabled-password cycode

USER cycode

CMD ["cycode"]
