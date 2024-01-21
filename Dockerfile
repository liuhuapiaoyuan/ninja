FROM alpine:3.16.6

LABEL name chatgpt-gateway
LABEL url https://github.com/gngpp/ninja

ENV LANG=C.UTF-8 DEBIAN_FRONTEND=noninteractive LANG=zh_CN.UTF-8 LANGUAGE=zh_CN.UTF-8 LC_ALL=C

# 创建目录 /root/.auth
COPY  ./har/.auth /root/.auth
COPY  ./har/.gpt4 /root/.gpt4
COPY  ./target/release/ninja /bin/chatgpt-gateway

ENTRYPOINT ["/bin/chatgpt-gateway"]