FROM envoyproxy/envoy:v1.31-latest

COPY envoy/envoy.yaml /app/envoy-original.yaml
COPY envoy/entrypoint.sh /app/entrypoint.sh

RUN chmod +x /app/entrypoint.sh

EXPOSE 8080
ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["-c", "/app/envoy.yaml", "--log-path", "/app/envoy.log"]
