import multiprocessing

#worker_class = "gevent"
workers = min(6, multiprocessing.cpu_count())
bind = "0.0.0.0:9696"
timeout = 90
keepalive = 3600
preload_app = True