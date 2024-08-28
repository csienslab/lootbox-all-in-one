# build chiavdf wheel
FROM python:3.12-slim-bookworm AS chiavdf-builder

RUN apt-get update && apt-get install -y \
    build-essential \
    git \
    cmake \
    libgmp-dev \
    libboost-all-dev \
    && rm -rf /var/lib/apt/lists/*
COPY ./chiavdf /chiavdf
WORKDIR /chiavdf
RUN git init && \
    python -m venv venv && \
    ./venv/bin/pip wheel .

# setup main image
FROM python:3.12-bookworm

# copy wheels and source code
RUN mkdir /wheels
COPY --from=chiavdf-builder /chiavdf/*.whl /wheels/
COPY headstart_py /headstart_py
COPY loot-box-protocol /loot-box-protocol
WORKDIR /

# install dependencies
RUN python -m venv venv && \
    . ./venv/bin/activate && \
    pip install /wheels/*.whl && \
    (cd headstart_py && pip install .) && \
    pip install -r loot-box-protocol/requirements.txt

# setup entrypoint
COPY init.sh .
CMD ["bash", "--init-file", "init.sh"]
