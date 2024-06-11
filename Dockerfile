FROM golang:1.21.0-alpine3.18 AS builder


WORKDIR /app

COPY go.mod ./
COPY go.sum ./
RUN go mod download

COPY . ./

RUN go build -o /app/tlz 


EXPOSE 4005

ENTRYPOINT [ "/app/tlz" ]

