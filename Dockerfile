FROM python:3.13-slim

RUN groupadd --system --gid 10001 iris \
    && useradd --system --uid 10001 --gid iris --create-home iris
WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN python -m pip install --no-cache-dir .

COPY config ./config
COPY evidence ./evidence
RUN mkdir -p /output && chown iris:iris /output

USER iris
ENTRYPOINT ["iris-audit"]
CMD ["evaluate", "--input", "evidence/sample/collector.json", "--output", "/output"]
