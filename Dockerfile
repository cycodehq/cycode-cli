FROM python:3.12.6-alpine3.20 AS base
WORKDIR /usr/cycode/app
RUN apk add git=2.45.2-r0

FROM base AS builder
ENV POETRY_VERSION=1.8.3

# deps are required to build cffi
RUN apk add --no-cache --virtual .build-deps gcc=13.2.1_git20240309-r0 libffi-dev=3.4.6-r0 musl-dev=1.2.5-r0 &&  \
    pip install --no-cache-dir "poetry==$POETRY_VERSION" "poetry-dynamic-versioning[plugin]" &&  \
    apk del .build-deps gcc libffi-dev musl-dev

COPY pyproject.toml poetry.lock README.md ./
# to be able to automatically detect version from Git Tag
COPY .git ./.git
# src
COPY cycode ./cycode
RUN poetry config virtualenvs.in-project true && \
    poetry --no-cache install --only=main --no-root && \
    poetry build

FROM base AS final
COPY --from=builder /usr/cycode/app/dist ./
RUN pip install --no-cache-dir cycode*.whl

# Add cycode group and user, alpine way
# https://wiki.alpinelinux.org/wiki/Setting_up_a_new_user
RUN addgroup -g 5000 cycode-group
RUN adduser --home /home/cycode --uid 5001 -G cycode-group --shell /bin/sh --disabled-password cycode

USER cycode

CMD ["cycode"]
