FROM python:3.8-buster as build-env
WORKDIR  app
COPY . ./
RUN python -m pip install --upgrade pip setuptools wheel
RUN python3 setup.py sdist bdist_wheel

FROM python:3.8-slim-buster
RUN apt-get update && apt-get install -y git --no-install-recommends
WORKDIR  app
COPY --from=build-env /app/dist ./
RUN pip install cycode*.whl
CMD ["cycode"]