FROM alpine:3.20

RUN apk add --no-cache ca-certificates wget

COPY --from=openpolicyagent/opa:0.64.1-static /opa /opa

USER 65532:65532

ENTRYPOINT ["/opa"]