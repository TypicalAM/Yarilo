FROM envoyproxy/envoy:v1.22.0

ARG CONFIG_FILE=envoy.yaml

COPY ${CONFIG_FILE} /etc/envoy/envoy.yaml

ENTRYPOINT [ "/usr/local/bin/envoy" ]
CMD [ "-c /etc/envoy/envoy.yaml", "-l trace", "--log-path /tmp/envoy_info.log" ]
