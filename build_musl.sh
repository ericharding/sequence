#!/bin/sh
docker run -v $PWD:/volume --rm -t clux/muslrust cargo build --release 