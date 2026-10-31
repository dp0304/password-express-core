# SPDX-License-Identifier: Apache-2.0
# AI Pass self-host node — multi-stage build, runs as an unprivileged user.
# Build from the open-source/ directory:  docker build -f deploy/Dockerfile -t aipass-node .
FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p aipass-node -p aipass-cli \
 && strip target/release/aipass-node target/release/aipass

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates tini \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system --gid 10001 aipass \
 && useradd --system --uid 10001 --gid aipass --home-dir /var/lib/aipass --shell /usr/sbin/nologin aipass \
 && install -d -m 0700 -o aipass -g aipass /var/lib/aipass /etc/aipass
COPY --from=build /src/target/release/aipass-node /usr/local/bin/aipass-node
COPY --from=build /src/target/release/aipass /usr/local/bin/aipass
COPY deploy/node.docker.toml /etc/aipass/node.toml
USER aipass:aipass
ENV AIPASS_NODE_CONFIG=/etc/aipass/node.toml
VOLUME ["/var/lib/aipass"]
EXPOSE 7878
HEALTHCHECK --interval=30s --timeout=3s CMD ["/usr/local/bin/aipass-node", "health"]
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/aipass-node"]
CMD ["run"]
