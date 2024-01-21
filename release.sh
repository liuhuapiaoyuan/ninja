set -e

docker build . -t liuhuapiaoyuan/chatgpt-gateway:latest
# 修改镜像标签为当前日期时间
time=$(date "+%Y%m%d%H%M%S")
docker tag liuhuapiaoyuan/chatgpt-gateway:latest liuhuapiaoyuan/chatgpt-gateway:$time
# 推送镜像到docker hub
docker push liuhuapiaoyuan/chatgpt-gateway:latest
docker push liuhuapiaoyuan/chatgpt-gateway:$time