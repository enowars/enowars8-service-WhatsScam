import multiprocessing

#worker_class = "gevent"
workers = 3 #min(4, multiprocessing.cpu_count())
bind = "0.0.0.0:9696"
timeout = 90
keepalive = 3600
preload_app = True