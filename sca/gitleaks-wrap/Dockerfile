FROM ghcr.io/oasm-platform/connector-gitleaks:8.30.1
USER root
COPY entrypoint.sh /proxy-fix.sh
RUN chmod +x /proxy-fix.sh
USER connector
ENTRYPOINT [/proxy-fix.sh]
