FROM python:3.8.16-alpine3.17 as base
WORKDIR /usr/cycode/app

FROM base as builder
ENV POETRY_VERSION=1.4.2

# deps are required to build cffi
RUN apk add --no-cache --virtual .build-deps gcc libffi-dev musl-dev &&  \
    pip install "poetry==$POETRY_VERSION" &&  \
    apk del .build-deps gcc libffi-dev musl-dev

COPY pyproject.toml poetry.lock README.md ./
COPY cycode ./cycode
RUN poetry config virtualenvs.in-project true && \
    poetry install --only=main --no-root && \
    poetry build

FROM base as final
RUN apk add git=2.38.5-r0
COPY --from=builder /usr/cycode/app/dist ./
RUN pip install --no-cache-dir cycode*.whl

# Add cycode group and user, alpine way
# https://wiki.alpinelinux.org/wiki/Setting_up_a_new_user
RUN addgroup -g 5000 cycode-group
RUN adduser --home /home/cycode --uid 5001 -G cycode-group --shell /bin/sh --disabled-password cycode

USER cycode

CMD ["cycode"]
