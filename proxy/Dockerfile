FROM envoyproxy/envoy:v1.22.0

ARG CONFIG_FILE=envoy.yaml
ARG SERVER_ADDR=0.0.0.0

COPY ${CONFIG_FILE} /etc/envoy/envoy.yaml
RUN sed -i "s/SERVER_ADDR/$SERVER_ADDR/g" /etc/envoy/envoy.yaml

ENTRYPOINT [ "/usr/local/bin/envoy" ]
CMD [ "-c /etc/envoy/envoy.yaml", "-l trace", "--log-path /tmp/envoy_info.log" ]
