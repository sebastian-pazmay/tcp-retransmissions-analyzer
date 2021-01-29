## Base image python:3.8-slim-buster
FROM python:3.8-slim-buster@sha256:520525c413176216f38aa55dee5aff761a084ca779f5e30c49dfd4854a857141
ARG SCRIPT
ENV pythonScript=$SCRIPT

COPY requirements.txt .
COPY ./sample-captures sample-captures/
COPY ./scripts .

RUN apt update && apt upgrade -y && \
    apt install -y tshark && \
    pip install --user -r requirements.txt

CMD ["sh", "-c", "python3 ${pythonScript}.py"]
