FROM node:20.11.1 as builder
#컨테이너 내부 /app경로에서 작업 수행
WORKDIR /app
# 패키지 install 캐싱을 위해 먼저 copy
COPY package.json .
RUN npm install
# 나머지 copy후 빌드
COPY ./ ./
RUN npm run build || exit 1

FROM node:20.11.1
WORKDIR /app
# 빌드된 애플리케이션 복사
COPY --from=builder /app/dist /app/dist
# serve 설치
RUN npm install -g serve
# front 포트
EXPOSE 5173
# front 웹서버 실행
ENTRYPOINT ["serve", "-l", "5173", "-s", "dist"] 