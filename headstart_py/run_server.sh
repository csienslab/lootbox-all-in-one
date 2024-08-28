#!/bin/sh
gunicorn -k gevent --bind 0.0.0.0:5000 headstart.server:app
