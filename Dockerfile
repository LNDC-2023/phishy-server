FROM python:3.9.18-slim
WORKDIR /
COPY . .
RUN pip install -r requirements.txt
EXPOSE 5000
CMD ["flask", "--app", "src/app", "run", "--host", "0.0.0.0"]