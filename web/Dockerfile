FROM python:3.8
WORKDIR /usr/src/app
COPY . .
RUN pip install --no-cache-dir -r requierments.txt
RUN pip install tensorflow-2.6.0-cp38-cp38-manylinux2010_x86_64.whl
CMD [ "python", "app.py" ]