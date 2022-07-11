FROM python:3.8-buster as build-env
WORKDIR /usr/cycode/app
COPY . ./
RUN python -m pip install --upgrade --no-cache-dir pip==22.0.4 setuptools==57.5.0 wheel==0.37.1
RUN python3 setup.py sdist bdist_wheel

FROM python:3.8-slim-buster
RUN apt-get update && apt-get install -y git=1:2.20.1-2+deb10u3 --no-install-recommends
WORKDIR /usr/cycode/app
COPY --from=build-env usr/cycode/app/dist ./
RUN pip install --no-cache-dir cycode*.whl

RUN groupadd -r user && useradd -r -g user user

USER user

CMD ["cycode"]