FROM envoyproxy/envoy:v1.31-latest

COPY envoy/envoy.yaml /app/envoy.yaml

EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/envoy"]
CMD ["-c", "/app/envoy.yaml", "--log-path", "/app/envoy.log"]
