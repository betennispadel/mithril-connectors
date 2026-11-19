FROM ghcr.io/oasm-platform/connector-trivy:0.76.2
USER root
COPY entrypoint.sh /proxy-fix.sh
RUN chmod +x /proxy-fix.sh
USER connector
ENTRYPOINT ["/proxy-fix.sh"]
