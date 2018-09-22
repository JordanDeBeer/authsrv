FROM golang:alpine as builder
RUN apk update && apk add git
RUN adduser -D appuser
COPY . $GOPATH/src/authsrv/
WORKDIR $GOPATH/src/authsrv/
RUN go get -d -v
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -installsuffix cgo -ldflags="-w -s" -o /go/bin/authsrv

FROM scratch
COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /go/bin/authsrv /app/authsrv
USER appuser

EXPOSE 8080
CMD ["/app/authsrv"]
