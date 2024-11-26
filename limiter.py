import time

class Limiter:
    def __init__(self, max_requests: int, time_window: float, forward_cb, drop_cb):
        self.max_requests = max_requests
        self.time_window = time_window
        self.forward_cb = forward_cb
        self.drop_cb = drop_cb
        self.requests = []

    def handle(self, packet):
        current = time.time()
        window_start = current - self.time_window
        self.requests.append(current)
        self.requests = list(filter(lambda t: t > window_start, self.requests))
        if len(self.requests) <= self.max_requests:
            self.forward_cb(packet)
        else:
            self.drop_cb(packet)
