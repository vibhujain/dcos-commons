FROM ubuntu:16.04

RUN apt-get -y update && \
    apt-get -y upgrade && \
    apt-get -y install wget software-properties-common

# Install Java, Python, and all their pre-reqs
RUN apt-get -y install pkg-config \
    zip \
    g++ \
    zlib1g-dev \
    unzip \
    openjdk-8-jdk \
    python

ENV JAVA_HOME /usr/lib/jvm/java-8-openjdk-amd64

RUN echo "export PATH=$PATH:$JAVA_HOME/bin" >> ~/.bashrc

CMD ["bash"]

